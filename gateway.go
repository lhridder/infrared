package infrared

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Lukaesebrot/mojango"
	"github.com/asaskevich/govalidator"
	"github.com/cloudflare/tableflip"
	"github.com/go-redis/redis/v8"
	"github.com/gofrs/uuid"
	"github.com/haveachin/infrared/protocol"
	"github.com/haveachin/infrared/protocol/cfb8"
	"github.com/haveachin/infrared/protocol/handshaking"
	"github.com/haveachin/infrared/protocol/login"
	"github.com/haveachin/infrared/protocol/status"
	"github.com/oschwald/geoip2-golang"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	usedBandwith = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "infrared_used_bandwith",
		Help: "The total number of used bytes of bandwith per proxy",
	}, []string{"host"})
	ctx = context.Background()
	Upg *tableflip.Upgrader
)

type Gateway struct {
	listeners            sync.Map
	Proxies              sync.Map
	closed               chan bool
	wg                   sync.WaitGroup
	conngroup            sync.WaitGroup
	ReceiveProxyProtocol bool
	underAttack          bool
	connections          uint64
	db                   *geoip2.Reader
	api                  *mojango.Client
	rdb                  *redis.Client
	publicKey            []byte
	privateKey           *rsa.PrivateKey
}

type Session struct {
	username        string
	loginPacket     protocol.Packet
	handshakePacket protocol.Packet
	country         string
	ip              string
	serverAddress   string
	connRemoteAddr  net.Addr
	ProtocolVersion protocol.VarInt
	config          *ProxyConfig
}

type iprisk struct {
	Datacenter   bool `json:"data_center"`
	PublicProxy  bool `json:"public_proxy"`
	TorExitRelay bool `json:"tor_exit_relay"`
}

func (gateway *Gateway) LoadDB() error {
	err := error(nil)
	gateway.db, err = geoip2.Open(Config.GeoIP.DatabaseFile)
	return err
}

func (gateway *Gateway) LoadMojangAPI() {
	gateway.api = mojango.New()
}

func (gateway *Gateway) ConnectRedis() error {
	gateway.rdb = redis.NewClient(&redis.Options{
		Addr:     Config.Redis.Host + ":6379",
		Password: Config.Redis.Pass,
		DB:       Config.Redis.DB,
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

	if Config.UnderAttack {
		log.Println("Enabled permanent underAttack mode")
		gateway.underAttack = true
		underAttackStatus.Set(1)
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

		if Config.Tableflip.Enabled {
			var listen net.Listener
			var err error
			listen, err = net.Listen("tcp", bind)
			if err != nil {
				if strings.Contains(err.Error(), "bind: address already in use") {
					log.Printf("Starting secondary prometheus listener on %s", Config.Prometheus.Bind2)
					listen, err = net.Listen("tcp", Config.Prometheus.Bind2)
					if err != nil {
						log.Printf("Failed to open secondary prometheus listener: %s", err)
						return
					}
				} else {
					log.Printf("Failed to open new prometheus listener: %s", err)
					return
				}
			}
			http.Serve(listen, nil)
		} else {
			http.ListenAndServe(bind, nil)
		}
	}()

	log.Println("Enabling Prometheus metrics endpoint on", bind)
	return nil
}

func (gateway *Gateway) GenerateKeys() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}
	gateway.privateKey = privateKey

	gateway.publicKey, err = x509.MarshalPKIXPublicKey(&gateway.privateKey.PublicKey)
	if err != nil {
		return err
	}
	return nil
}

func (gateway *Gateway) KeepProcessActive() {
	gateway.wg.Wait()
}

func (gateway *Gateway) WaitConnGroup() {
	gateway.conngroup.Wait()
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
	log.Println("Closing config with UID", proxyUID)
	v, ok := gateway.Proxies.Load(proxyUID)
	if !ok {
		return
	}
	proxy := v.(*Proxy)

	uids := proxy.UIDs()
	for _, uid := range uids {
		log.Println("Closing proxy with UID", uid)
		gateway.Proxies.Delete(uid)
	}

	playersConnected.DeleteLabelValues(proxy.DomainName())

	closeListener := true
	gateway.Proxies.Range(func(k, v interface{}) bool {
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
		gateway.Proxies.Store(uid, proxy)
	}
	proxyUID := proxy.UID()

	proxy.Config.removeCallback = func() {
		gateway.CloseProxy(proxyUID)
	}

	proxy.Config.changeCallback = func() {
		gateway.CloseProxy(proxyUID)
		if err := gateway.RegisterProxy(proxy); err != nil {
			log.Println(err)
		}
	}

	playersConnected.WithLabelValues(proxy.DomainName())

	if Config.TrackBandwidth {
		usedBandwith.WithLabelValues(proxy.DomainName())
	}

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
			gateway.conngroup.Add(1)
			if Config.Debug {
				log.Printf("[>] Incoming %s on listener %s", conn.RemoteAddr(), addr)
			}
			if gateway.underAttack {
				defer conn.CloseForce()
			} else {
				defer conn.Close()
			}

			realip := conn.RemoteAddr()
			if gateway.ReceiveProxyProtocol {
				header, err := proxyproto.Read(conn.Reader())
				if err != nil {
					if Config.Debug {
						log.Printf("[e] failed to parse proxyproto for %s: %s", conn.RemoteAddr(), err)
					}
					return
				}
				realip = header.SourceAddr
			}

			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := gateway.serve(conn, addr, realip); err != nil {
				if errors.Is(err, protocol.ErrInvalidPacketID) || errors.Is(err, protocol.ErrInvalidPacketLength) {
					if Config.GeoIP.Enabled {
						ip, _, err := net.SplitHostPort(realip.String())
						if err != nil {
							log.Printf("[i] failed to split ip and port for %s: %s", realip, err)
						}

						record, err := gateway.db.Country(net.ParseIP(ip))
						if err != nil {
							log.Printf("[i] failed to lookup country for %s", realip)
						}
						handshakeCount.With(prometheus.Labels{"type": "cancelled_invalid", "host": "", "country": record.Country.IsoCode}).Inc()

						err = gateway.rdb.Set(ctx, "ip:"+ip, "false,"+record.Country.IsoCode, time.Hour*12).Err()
					} else {
						handshakeCount.With(prometheus.Labels{"type": "cancelled_invalid", "host": "", "country": ""}).Inc()
					}
				}

				if Config.Debug {
					log.Printf("[x] %s closed connection with %s; error: %s", realip, addr, err)
				}
				gateway.conngroup.Done()
				return
			}
			_ = conn.SetDeadline(time.Time{})
			if Config.Debug {
				log.Printf("[x] %s closed connection with %s", realip, addr)
			}
			gateway.conngroup.Done()
		}()
	}
}

func (gateway *Gateway) serve(conn Conn, addr string, realip net.Addr) (rerr error) {
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

	atomic.AddUint64(&gateway.connections, 1)

	session := Session{}

	session.connRemoteAddr = realip

	err := error(nil)
	session.handshakePacket, err = conn.ReadPacket(true)
	if err != nil {
		return err
	}

	hs, err := handshaking.UnmarshalServerBoundHandshake(session.handshakePacket)
	if err != nil {
		return err
	}
	session.ProtocolVersion = hs.ProtocolVersion

	session.serverAddress = strings.ToLower(hs.ParseServerAddress())
	if !govalidator.IsDNSName(session.serverAddress) && !govalidator.IsIP(session.serverAddress) {
		return errors.New(session.serverAddress + " is not a valid domain")
	}

	proxyUID := proxyUID(session.serverAddress, addr)
	if Config.Debug {
		log.Printf("[i] %s requests proxy with UID %s", session.connRemoteAddr, proxyUID)
	}

	session.ip, _, _ = net.SplitHostPort(session.connRemoteAddr.String())

	v, ok := gateway.Proxies.Load(proxyUID)
	if !ok {
		if hs.IsLoginRequest() {
			err := gateway.handleUnknown(conn, session, true)
			if err != nil {
				return err
			}
		}
		err := gateway.handleUnknown(conn, session, false)
		if err != nil {
			return err
		}
	}
	proxy := v.(*Proxy)
	session.config = proxy.Config

	if hs.IsLoginRequest() {
		session.loginPacket, err = conn.ReadPacket(true)
		if err != nil {
			return err
		}

		loginStart, err := login.UnmarshalServerBoundLoginStart(session.loginPacket)
		if err != nil {
			return err
		}

		session.username = string(loginStart.Name)

		if Config.GeoIP.Enabled {
			err := gateway.geoCheck(conn, &session)
			if err != nil {
				return err
			}

			if Config.MojangAPIenabled && !gateway.underAttack && !session.config.AllowCracked {
				err := gateway.usernameCheck(&session)
				if err != nil {
					return err
				}
			}
		}
		handshakeCount.With(prometheus.Labels{"type": "login", "host": session.serverAddress, "country": session.country}).Inc()
		_ = conn.SetDeadline(time.Time{})
		if err := proxy.handleLoginConnection(conn, session); err != nil {
			return err
		}
	}

	if hs.IsStatusRequest() {
		if Config.GeoIP.Enabled {
			record, err := gateway.db.Country(net.ParseIP(session.ip))
			session.country = record.Country.IsoCode
			if err != nil {
				log.Printf("[i] failed to lookup country for %s", session.connRemoteAddr)
			}
		}
		handshakeCount.With(prometheus.Labels{"type": "status", "host": session.serverAddress, "country": session.country}).Inc()
		if err := proxy.handleStatusConnection(conn, session); err != nil {
			return err
		}
	}
	return nil
}

func (gateway *Gateway) handleUnknown(conn Conn, session Session, isLogin bool) error {
	if gateway.underAttack {
		return errors.New("blocked connection because underAttack")
	}

	if Config.GeoIP.Enabled {
		record, err := gateway.db.Country(net.ParseIP(session.ip))
		session.country = record.Country.IsoCode
		if err != nil {
			log.Printf("[i] failed to lookup country for %s", session.connRemoteAddr)
		}
	}

	if !isLogin {
		_, err := conn.ReadPacket(true)
		if err != nil {
			return err
		}

		err = conn.WritePacket(DefaultStatusResponse())
		if err != nil {
			return err
		}

		pingPacket, err := conn.ReadPacket(true)
		if err != nil {
			return err
		}

		ping, err := status.UnmarshalServerBoundPing(pingPacket)
		if err != nil {
			return err
		}

		err = conn.WritePacket(status.ClientBoundPong{
			Payload: ping.Payload,
		}.Marshal())
		if err != nil {
			return err
		}

		handshakeCount.With(prometheus.Labels{"type": "status", "host": session.serverAddress, "country": session.country}).Inc()
		return errors.New("no proxy with domain " + session.serverAddress)
	}

	// Client send an invalid address/port; we don't have a v for that address
	err := conn.WritePacket(login.ClientBoundDisconnect{
		Reason: protocol.Chat(fmt.Sprintf("{\"text\":\"%s\"}", Config.GenericJoinResponse)),
	}.Marshal())
	if err != nil {
		log.Println(err)
	}
	handshakeCount.With(prometheus.Labels{"type": "login", "host": session.serverAddress, "country": session.country}).Inc()

	return errors.New("no proxy with domain " + session.serverAddress)
}

func (gateway *Gateway) geoCheck(conn Conn, session *Session) error {
	result, err := gateway.rdb.Get(ctx, "ip:"+session.ip).Result()
	if err == redis.Nil {
		record, err := gateway.db.Country(net.ParseIP(session.ip))
		if err != nil {
			log.Printf("[i] failed to lookup country for %s", session.connRemoteAddr)
		}
		session.country = record.Country.IsoCode

		if Config.GeoIP.EnableIprisk {
			var client http.Client

			req, err := http.NewRequest(http.MethodGet, "https://beta.iprisk.info/v1/"+session.ip, nil)
			if err != nil {
				return errors.New("cannot format request to iprisk because of " + err.Error())
			}
			req.Header.Set("User-Agent", "github.com/lhridder/infrared")

			res, err := client.Do(req)
			if err != nil {
				log.Printf("Cannot query iprisk for %s because of %s", session.ip, err.Error())
				return errors.New("cannot query iprisk because of " + err.Error())
			}

			if res.StatusCode != 200 {
				log.Printf("Failed to query iprisk for %s, status code %s", session.ip, strconv.Itoa(res.StatusCode))
				return errors.New("failed to query iprisk, error code: " + strconv.Itoa(res.StatusCode))
			}

			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return errors.New("failed to read iprisk response: " + err.Error())
			}

			var iprisk iprisk
			err = json.Unmarshal(body, &iprisk)
			if err != nil {
				return errors.New("failed to unmarshal iprisk response: " + err.Error())
			}

			if iprisk.TorExitRelay || iprisk.PublicProxy {
				err := kickBlocked(conn)
				if err != nil {
					return err
				}
				handshakeCount.With(prometheus.Labels{"type": "cancelled_ip", "host": session.serverAddress, "country": session.country}).Inc()

				err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
				if err != nil {
					log.Println(err)
				}
				return errors.New("blocked because iprisk tor/proxy")
			}

			if iprisk.Datacenter {
				if gateway.underAttack {
					err := kickBlocked(conn)
					if err != nil {
						return err
					}
					handshakeCount.With(prometheus.Labels{"type": "cancelled_ip", "host": session.serverAddress, "country": session.country}).Inc()

					err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
					if err != nil {
						log.Println(err)
					}
					return errors.New("blocked because iprisk datacenter during attack")
				}

				if Config.MojangAPIenabled && !session.config.AllowCracked {
					err := gateway.loginCheck(conn, session)
					if err != nil {
						return err
					}
				} else {
					handshakeCount.With(prometheus.Labels{"type": "cancelled", "host": session.serverAddress, "country": session.country}).Inc()

					err := kickRejoin(conn)
					if err != nil {
						return err
					}

					err = gateway.rdb.Set(ctx, "ip:"+session.ip, "half,"+session.country, time.Hour*24).Err()
					if err != nil {
						log.Println(err)
					}

					return errors.New("blocked for rejoin (geoip)")
				}
			} else {
				if gateway.underAttack {
					if Config.MojangAPIenabled && !session.config.AllowCracked {
						err := gateway.loginCheck(conn, session)
						if err != nil {
							return err
						}
					} else {
						handshakeCount.With(prometheus.Labels{"type": "cancelled", "host": session.serverAddress, "country": session.country}).Inc()

						err := kickRejoin(conn)
						if err != nil {
							return err
						}

						err = gateway.rdb.Set(ctx, "ip:"+session.ip, "half,"+session.country, time.Hour*24).Err()
						if err != nil {
							log.Println(err)
						}

						return errors.New("blocked for rejoin (geoip)")
					}
				} else {
					err = gateway.rdb.Set(ctx, "ip:"+session.ip, "half,"+session.country, time.Hour*24).Err()
					if err != nil {
						log.Println(err)
					}
				}
			}
		} else {
			if gateway.underAttack {
				if Config.MojangAPIenabled && !session.config.AllowCracked {
					err := gateway.loginCheck(conn, session)
					if err != nil {
						return err
					}
				} else {
					handshakeCount.With(prometheus.Labels{"type": "cancelled", "host": session.serverAddress, "country": session.country}).Inc()

					err := kickRejoin(conn)
					if err != nil {
						return err
					}
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
		session.country = results[1]

		if results[0] == "false" {
			err := kickBlocked(conn)
			if err != nil {
				return err
			}
			handshakeCount.With(prometheus.Labels{"type": "cancelled_cache", "host": session.serverAddress, "country": session.country}).Inc()
			gateway.rdb.TTL(ctx, "ip:"+session.ip).SetVal(time.Hour * 12)
			return errors.New("blocked because ip cached as false")
		}

		if gateway.underAttack {
			if Config.MojangAPIenabled && !session.config.AllowCracked {
				err := gateway.loginCheck(conn, session)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (gateway *Gateway) usernameCheck(session *Session) error {
	_, err := gateway.rdb.Get(ctx, "username:"+session.username).Result()
	if err == redis.Nil {
		_, err := gateway.api.FetchUUID(session.username)
		if err != nil {
			if err == mojango.ErrNoContent || err == mojango.ErrTooManyRequests {
				handshakeCount.With(prometheus.Labels{"type": "cancelled_name", "host": session.serverAddress, "country": session.country}).Inc()
				return errors.New("blocked because name")
			} else {
				return errors.New("Could not query Mojang: " + err.Error())
			}
		} else {
			err = gateway.rdb.Set(ctx, "username:"+session.username, "half", time.Hour*12).Err()
			if err != nil {
				log.Println(err)
			}
			err = gateway.rdb.Set(ctx, "ip:"+session.ip, "half,"+session.country, time.Hour*24).Err()
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
		gateway.rdb.TTL(ctx, "username:"+session.username).SetVal(time.Hour * 12)
		err = gateway.rdb.Set(ctx, "ip:"+session.ip, "half,"+session.country, time.Hour*24).Err()
		if err != nil {
			log.Println(err)
		}
	}
	return nil
}

func (gateway *Gateway) loginCheck(conn Conn, session *Session) error {
	result, err := gateway.rdb.Get(ctx, "ip:"+session.ip).Result()
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
	if results[0] != "true" {
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

		encryptionResponse, err := conn.ReadPacket(true)
		if err != nil {
			err := kickBlocked(conn)
			if err != nil {
				return err
			}
			handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
			err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
			return errors.New("cannot read encryption response")
		}

		encryptionRes, encryptionResNew, err := login.UnmarshalServerBoundEncryptionResponse(encryptionResponse, session.ProtocolVersion)
		if err != nil {
			err := kickBlocked(conn)
			if err != nil {
				return err
			}
			handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
			err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
			return errors.New("cannot parse encryption response")
		}

		var decryptedSharedSecret []byte
		if !reflect.ValueOf(encryptionResNew).IsZero() {
			decryptedSharedSecret, err = gateway.privateKey.Decrypt(rand.Reader, encryptionResNew.SharedSecret, nil)
			if err != nil {
				err := kickBlocked(conn)
				if err != nil {
					return err
				}
				handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
				err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
				return errors.New("failed to decrypt shared secret")
			}
			//TODO check signature and salt
		} else {
			decryptedVerifyToken, err := gateway.privateKey.Decrypt(rand.Reader, encryptionRes.VerifyToken, nil)
			if err != nil {
				err := kickBlocked(conn)
				if err != nil {
					return err
				}
				handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
				err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
				return errors.New("failed to decrypt verify token")
			}

			if !bytes.Equal(decryptedVerifyToken, verifyToken) {
				err := kickBlocked(conn)
				if err != nil {
					return err
				}
				handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
				err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
				return errors.New("invalid verify token")
			}

			decryptedSharedSecret, err = gateway.privateKey.Decrypt(rand.Reader, encryptionRes.SharedSecret, nil)
			if err != nil {
				err := kickBlocked(conn)
				if err != nil {
					return err
				}
				handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
				err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
				return errors.New("failed to decrypt shared secret")
			}
		}

		block, err := aes.NewCipher(decryptedSharedSecret)
		if err != nil {
			return errors.New("failed to start cypher")
		}

		notchHash := NewSha1Hash()
		notchHash.Update([]byte(""))
		notchHash.Update(decryptedSharedSecret)
		notchHash.Update(gateway.publicKey)
		hash := notchHash.HexDigest()

		url := "https://sessionserver.mojang.com/session/minecraft/hasJoined?username=" + session.username + "&serverId=" + hash

		resp, err := http.Get(url)
		if err != nil {
			return errors.New("failed to validate player with session server")
		}

		if resp.StatusCode != http.StatusOK {
			err := kickBlocked(conn)
			if err != nil {
				return err
			}
			handshakeCount.With(prometheus.Labels{"type": "cancelled_authentication", "host": session.serverAddress, "country": session.country}).Inc()
			err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
			return errors.New("unable to authenticate session " + resp.Status)
		}

		var p struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			return errors.New("failed to parse session server response")
		}
		_ = resp.Body.Close()

		if session.username != p.Name {
			err := kickBlocked(conn)
			if err != nil {
				return err
			}
			handshakeCount.With(prometheus.Labels{"type": "cancelled_authentication", "host": session.serverAddress, "country": session.country}).Inc()
			err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
			return errors.New("invalid username: " + session.username + " != " + p.Name)
		}

		playerUUID, err := uuid.FromString(p.ID)
		if err != nil {
			return errors.New("failed to parse player UUID")
		}

		conn.SetCipher(cfb8.NewEncrypter(block, decryptedSharedSecret), cfb8.NewDecrypter(block, decryptedSharedSecret))

		log.Printf("[i] %s finished encryption check with uuid %s", p.Name, playerUUID)

		err = kickRejoin(conn)
		if err != nil {
			return err
		}

		err = gateway.rdb.Set(ctx, "username:"+session.username, "true", time.Hour*12).Err()
		if err != nil {
			log.Println(err)
		}
		err = gateway.rdb.Set(ctx, "ip:"+session.ip, "true,"+session.country, time.Hour*24).Err()
		if err != nil {
			log.Println(err)
		}

		handshakeCount.With(prometheus.Labels{"type": "cancelled", "host": session.serverAddress, "country": session.country}).Inc()
		return errors.New("blocked for rejoin (auth)")
	}
	return nil
}

func (gateway *Gateway) ClearCps() {
	if gateway.connections >= Config.ConnectionThreshold {
		gateway.underAttack = true
		underAttackStatus.Set(1)
		log.Printf("[i] Reached connections treshold: %s", strconv.FormatUint(gateway.connections, 10))
		time.Sleep(time.Minute)
	} else {
		if gateway.underAttack {
			log.Printf("[i] Disabled connections treshold: %s", strconv.FormatUint(gateway.connections, 10))
			gateway.underAttack = false
			underAttackStatus.Set(0)
		}
	}
	gateway.connections = 0
	time.Sleep(time.Second)
}

func (gateway *Gateway) TrackBandwith() {
	gateway.Proxies.Range(func(k, v interface{}) bool {
		proxy := v.(*Proxy)
		name := proxy.DomainName()
		proxy.mu.Lock()
		usedBandwith.WithLabelValues(name).Add(float64(proxy.usedBandwith))
		proxy.usedBandwith = 0
		proxy.mu.Unlock()
		return false
	})
	time.Sleep(5 * time.Second)
}

func kickRejoin(conn Conn) error {
	return conn.WritePacket(login.ClientBoundDisconnect{
		Reason: protocol.Chat(fmt.Sprintf("{\"text\":\"%s\"}", Config.RejoinMessage)),
	}.Marshal())
}

func kickBlocked(conn Conn) error {
	return conn.WritePacket(login.ClientBoundDisconnect{
		Reason: protocol.Chat(fmt.Sprintf("{\"text\":\"%s\"}", Config.BlockedMessage)),
	}.Marshal())
}
