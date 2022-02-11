package infrared

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/Lukaesebrot/mojango"
	"github.com/asaskevich/govalidator"
	"github.com/go-redis/redis/v8"
	"github.com/haveachin/infrared/protocol"
	"github.com/haveachin/infrared/protocol/handshaking"
	"github.com/haveachin/infrared/protocol/login"
	"github.com/oschwald/geoip2-golang"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	handshakeCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "infrared_handshakes",
		Help: "The total number of handshakes made to each proxy by type",
	}, []string{"type", "host", "country"})
	underAttackStatus = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "infrared_underAttack",
		Help: "Is the proxy under attack",
	})
	ctx = context.Background()
)

type Gateway struct {
	listeners            sync.Map
	proxies              sync.Map
	closed               chan bool
	wg                   sync.WaitGroup
	receiveProxyProtocol bool
	underAttack          bool
	connections          int
	db                   *geoip2.Reader
	api                  *mojango.Client
	rdb                  *redis.Client
	publicKey            []byte
}

func (gateway *Gateway) LoadDB() {
	gateway.db, _ = geoip2.Open(GeoIPdatabasefile)
}

func (gateway *Gateway) LoadMojangAPI() {
	gateway.api = mojango.New()
}

func (gateway *Gateway) ConnectRedis() error {
	gateway.rdb = redis.NewClient(&redis.Options{
		Addr:     RedisHost + ":6379",
		Password: RedisPass,
		DB:       RedisDB,
	})
	_, err := gateway.rdb.Ping(ctx).Result()
	if err != nil {
		return err
	}
	return nil
}

func (gateway *Gateway) ListenAndServe(proxies []*Proxy) error {
	if len(proxies) <= 0 {
		return errors.New("no proxies in gateway")
	}

	gateway.closed = make(chan bool, len(proxies))

	for _, proxy := range proxies {
		if err := gateway.RegisterProxy(proxy); err != nil {
			gateway.Close()
			return err
		}
	}

	log.Println("All proxies are online")
	return nil
}

func (gateway *Gateway) EnablePrometheus(bind string) error {
	gateway.wg.Add(1)

	go func() {
		defer gateway.wg.Done()

		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(bind, nil)
	}()

	log.Println("Enabling Prometheus metrics endpoint on", bind)
	return nil
}

func (gateway *Gateway) GenerateKeys() error {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	gateway.publicKey, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	return nil
}

func (gateway *Gateway) KeepProcessActive() {
	gateway.wg.Wait()
}

// Close closes all listeners
func (gateway *Gateway) Close() {
	gateway.listeners.Range(func(k, v interface{}) bool {
		gateway.closed <- true
		_ = v.(Listener).Close()
		return false
	})
}

func (gateway *Gateway) CloseProxy(proxyUID string) {
	log.Println("Closing proxy with UID", proxyUID)
	v, ok := gateway.proxies.Load(proxyUID)
	if !ok {
		return
	}
	proxy := v.(*Proxy)

	uids := proxy.UIDs()
	for _, uid := range uids {
		log.Println("Closing proxy with UID", uid)
		gateway.proxies.Delete(uid)
	}

	closeListener := true
	gateway.proxies.Range(func(k, v interface{}) bool {
		otherProxy := v.(*Proxy)
		if proxy.ListenTo() == otherProxy.ListenTo() {
			closeListener = false
			return false
		}
		return true
	})

	if !closeListener {
		return
	}

	playersConnected.Delete(prometheus.Labels{"host": proxy.DomainName()})

	v, ok = gateway.listeners.Load(proxy.ListenTo())
	if !ok {
		return
	}
	v.(Listener).Close()
}

func (gateway *Gateway) RegisterProxy(proxy *Proxy) error {
	// Register new Proxy
	uids := proxy.UIDs()
	for _, uid := range uids {
		log.Println("Registering proxy with UID", uid)
		gateway.proxies.Store(uid, proxy)
	}
	proxyUID := proxy.UID()

	proxy.Config.removeCallback = func() {
		gateway.CloseProxy(proxyUID)
	}

	proxy.Config.changeCallback = func() {
		if proxyUID == proxy.UID() {
			return
		}
		gateway.CloseProxy(proxyUID)
		if err := gateway.RegisterProxy(proxy); err != nil {
			log.Println(err)
		}
	}

	playersConnected.WithLabelValues(proxy.DomainName())

	// Check if a gate is already listening to the Proxy address
	addr := proxy.ListenTo()
	if _, ok := gateway.listeners.Load(addr); ok {
		return nil
	}

	log.Println("Creating listener on", addr)
	listener, err := Listen(addr)
	if err != nil {
		return err
	}
	gateway.listeners.Store(addr, listener)

	gateway.wg.Add(1)
	go func() {
		if err := gateway.listenAndServe(listener, addr); err != nil {
			log.Printf("Failed to listen on %s; error: %s", proxy.ListenTo(), err)
		}
	}()
	return nil
}

func (gateway *Gateway) listenAndServe(listener Listener, addr string) error {
	defer gateway.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("Closing listener on", addr)
				gateway.listeners.Delete(addr)
				return nil
			}

			continue
		}

		go func() {
			log.Printf("[>] Incoming %s on listener %s", conn.RemoteAddr(), addr)
			defer conn.Close()
			if err := gateway.serve(conn, addr); err != nil {
				log.Printf("[x] %s closed connection with %s; error: %s", conn.RemoteAddr(), addr, err)
				return
			}
			log.Printf("[x] %s closed connection with %s", conn.RemoteAddr(), addr)
		}()
	}
}

func (gateway *Gateway) serve(conn Conn, addr string) (rerr error) {
	defer func() {
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				rerr = errors.New(x)
			case error:
				rerr = x
			default:
				rerr = errors.New("unknown panic in client handler")
			}
		}
	}()

	gateway.connections++

	connRemoteAddr := conn.RemoteAddr()
	if gateway.receiveProxyProtocol {
		header, err := proxyproto.Read(conn.Reader())
		if err != nil {
			return err
		}
		connRemoteAddr = header.SourceAddr
	}

	handshakePacket, err := conn.ReadPacket()
	if err != nil {
		return err
	}

	hs, err := handshaking.UnmarshalServerBoundHandshake(handshakePacket)
	if err != nil {
		return err
	}

	serverAddress := strings.ToLower(hs.ParseServerAddress())
	if !govalidator.IsDNSName(serverAddress) && !govalidator.IsIP(serverAddress) {
		return errors.New(serverAddress + " is not a valid domain")
	}

	proxyUID := proxyUID(serverAddress, addr)
	log.Printf("[i] %s requests proxy with UID %s", connRemoteAddr, proxyUID)

	v, ok := gateway.proxies.Load(proxyUID)
	if !ok {
		if gateway.underAttack {
			_ = conn.Close()
			return nil
		}
		if hs.IsStatusRequest() {
			_, err := conn.ReadPacket()
			if err != nil {
				return err
			}

			err = conn.WritePacket(DefaultStatusResponse())
			if err != nil {
				return err
			}

			pingPk, _ := conn.ReadPacket()
			err = conn.WritePacket(pingPk)
			if err != nil {
				return err
			}
		}

		// Client send an invalid address/port; we don't have a v for that address
		err := conn.WritePacket(login.ClientBoundDisconnect{
			Reason: protocol.Chat(fmt.Sprintf("{\"text\":\"%s\"}", "There is no proxy associated with this domain. Please check your configuration.")),
		}.Marshal())
		if err != nil {
			log.Println(err)
		}

		return errors.New("no proxy with uid " + proxyUID)
	}
	proxy := v.(*Proxy)

	ip, _, _ := net.SplitHostPort(connRemoteAddr.String())
	country := ""
	if hs.IsLoginRequest() {
		loginPacket, err := conn.ReadPacket()
		if err != nil {
			return err
		}
		if GeoIPenabled {
			result, err := gateway.rdb.Get(ctx, "ip:"+ip).Result()
			if err == redis.Nil {
				record, err := gateway.db.Country(net.ParseIP(ip))
				if err != nil {
					log.Printf("[i] failed to lookup country for %s", connRemoteAddr)
				}

				country = record.Country.IsoCode
				if gateway.underAttack {
					err = conn.WritePacket(login.ClientBoundDisconnect{
						Reason: protocol.Chat(fmt.Sprintf("{\"text\":\"%s\"}", "Please rejoin to verify your connection.")),
					}.Marshal())
					if err != nil {
						log.Println(err)
					}

					err := conn.Close()
					if err != nil {
						log.Println(err)
					}

					if contains(CountryWhitelist, country) {
						err = gateway.rdb.Set(ctx, "ip:"+ip, "true,"+country, time.Hour*24).Err()
						if err != nil {
							log.Println(err)
						}
					} else {
						err = gateway.rdb.Set(ctx, "ip:"+ip, "false,"+country, time.Hour*12).Err()
						if err != nil {
							log.Println(err)
						}
					}

					handshakeCount.With(prometheus.Labels{"type": "cancelled_ip", "host": serverAddress, "country": country}).Inc()
					return errors.New("blocked")
				} else {
					if contains(CountryWhitelist, country) {
						err = gateway.rdb.Set(ctx, "ip:"+ip, "true,"+country, time.Hour*24).Err()
						if err != nil {
							log.Println(err)
						}
					}
				}
			} else {
				if err != nil {
					if err == redis.ErrClosed {
						err := gateway.ConnectRedis()
						if err != nil {
							return err
						}
					} else {
						return err
					}
				}
				results := strings.Split(result, ",")
				status, _ := strconv.ParseBool(results[0])
				country = results[1]
				if status == false && gateway.underAttack {
					err := conn.Close()
					if err != nil {
						log.Println(err)
					}
					handshakeCount.With(prometheus.Labels{"type": "cancelled_ip", "host": serverAddress, "country": country}).Inc()
					gateway.rdb.TTL(ctx, "ip:"+ip).SetVal(time.Hour * 12)
					log.Printf("[i] Blocked %s from joining because they joined during an attack.", connRemoteAddr)
					return errors.New("blocked")
				}
			}
			if MojangAPIenabled {
				if gateway.underAttack {
					verifyToken := make([]byte, 4)
					if _, err := rand.Read(verifyToken); err != nil {
						return err
					}

					err = conn.WritePacket(login.ClientBoundEncryptionRequest{
						ServerID:    "",
						PublicKey:   gateway.publicKey,
						VerifyToken: verifyToken,
					}.Marshal())
					if err != nil {
						return err
					}

					encryptionResponse, err := conn.ReadPacket()
					_, err = login.UnmarshalServerBoundEncryptionResponse(encryptionResponse)
					if err != nil {
						handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": serverAddress, "country": country}).Inc()
						err = gateway.rdb.Set(ctx, "ip:"+ip, "false,"+country, time.Hour*12).Err()
						return errors.New("invalid login response")
					}

					err = gateway.rdb.Set(ctx, "ip:"+ip, "true,"+country, time.Hour*24).Err()
					if err != nil {
						log.Println(err)
					}

					handshakeCount.With(prometheus.Labels{"type": "cancelled", "host": serverAddress, "country": country}).Inc()
					return errors.New("blocked")
				}

				ls, err := login.UnmarshalServerBoundLoginStart(loginPacket)
				if err != nil {
					return err
				}

				name := string(ls.Name)

				_, err = gateway.rdb.Get(ctx, "username:"+name).Result()
				if err == redis.Nil {
					uuid, err := gateway.api.FetchUUID(name)
					if err != nil {
						if err == mojango.ErrNoContent || err == mojango.ErrTooManyRequests {
							handshakeCount.With(prometheus.Labels{"type": "cancelled_name", "host": serverAddress, "country": country}).Inc()
							log.Printf("[i] Blocked %s from joining because of name %s", connRemoteAddr, name)
							return errors.New("blocked because name")
						} else {
							return errors.New("Could not query Mojang: " + err.Error())
						}
					} else {
						log.Printf("[i] Looked up %s with username %s to uuid %s", connRemoteAddr, name, uuid)

						err = gateway.rdb.Set(ctx, "username:"+name, "true", time.Hour*12).Err()
						if err != nil {
							log.Println(err)
						}
						err = gateway.rdb.Set(ctx, "ip:"+ip, "true,"+country, time.Hour*24).Err()
						if err != nil {
							log.Println(err)
						}
					}
				} else {
					if err != nil {
						if err == redis.ErrClosed {
							err := gateway.ConnectRedis()
							if err != nil {
								return err
							}
						} else {
							return err
						}
					}
					gateway.rdb.TTL(ctx, "username:"+name).SetVal(time.Hour * 12)
					err = gateway.rdb.Set(ctx, "ip:"+ip, "true,"+country, time.Hour*24).Err()
					if err != nil {
						log.Println(err)
					}
				}
			}
		}
		handshakeCount.With(prometheus.Labels{"type": "login", "host": serverAddress, "country": country}).Inc()
		if err := proxy.handleConn(conn, connRemoteAddr, handshakePacket, loginPacket); err != nil {
			return err
		}
	}

	if hs.IsStatusRequest() {
		record, err := gateway.db.Country(net.ParseIP(ip))
		country = record.Country.IsoCode
		if err != nil {
			log.Printf("[i] failed to lookup country for %s", connRemoteAddr)
		}
		handshakeCount.With(prometheus.Labels{"type": "status", "host": serverAddress, "country": country}).Inc()
		if err := proxy.handleConn(conn, connRemoteAddr, handshakePacket, handshakePacket); err != nil {
			return err
		}
	}
	return nil
}

func (gateway *Gateway) ClearCps() {
	if gateway.connections >= 20 {
		gateway.underAttack = true
		underAttackStatus.Set(1)
		log.Printf("[i] Reached connections treshold: %s", strconv.Itoa(gateway.connections))
		time.Sleep(time.Minute)
	} else {
		if gateway.underAttack {
			log.Printf("[i] Disabled connections treshold: %s", strconv.Itoa(gateway.connections))
			gateway.underAttack = false
			underAttackStatus.Set(0)
		}
	}
	gateway.connections = 0
	time.Sleep(time.Second)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
