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
	"log"
	"net"
	"net/http"
	"reflect"
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
	Proxies              sync.Map
	closed               chan bool
	wg                   sync.WaitGroup
	ReceiveProxyProtocol bool
	underAttack          bool
	connections          int
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
	HasSigData      protocol.Boolean
	Timestamp       protocol.Long
	PublicKey       protocol.ByteArray
	Signature       protocol.ByteArray
	ProtocolVersion protocol.VarInt
}

func (gateway *Gateway) LoadDB() error {
	err := error(nil)
	gateway.db, err = geoip2.Open(Config.GeoIPdatabasefile)
	return err
}

func (gateway *Gateway) LoadMojangAPI() {
	gateway.api = mojango.New()
}

func (gateway *Gateway) ConnectRedis() error {
	gateway.rdb = redis.NewClient(&redis.Options{
		Addr:     Config.RedisHost + ":6379",
		Password: Config.RedisPass,
		DB:       Config.RedisDB,
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
		http.ListenAndServe(bind, nil)
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
			if Config.Debug {
				log.Printf("[>] Incoming %s on listener %s", conn.RemoteAddr(), addr)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := gateway.serve(conn, addr); err != nil {
				if errors.Is(err, protocol.ErrInvalidPacketID) || errors.Is(err, protocol.ErrInvalidPacketLength) {
					handshakeCount.With(prometheus.Labels{"type": "cancelled_invalid", "host": "", "country": ""}).Inc()
				}

				if Config.Debug {
					log.Printf("[x] %s closed connection with %s; error: %s", conn.RemoteAddr(), addr, err)
				}
				return
			}
			_ = conn.SetDeadline(time.Time{})
			if Config.Debug {
				log.Printf("[x] %s closed connection with %s", conn.RemoteAddr(), addr)
			}
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

	session := Session{}

	session.connRemoteAddr = conn.RemoteAddr()
	if gateway.ReceiveProxyProtocol {
		header, err := proxyproto.Read(conn.Reader())
		if err != nil {
			return err
		}
		session.connRemoteAddr = header.SourceAddr
	}

	err := error(nil)
	session.handshakePacket, err = conn.ReadPacket()
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

	if hs.IsLoginRequest() {
		session.loginPacket, err = conn.ReadPacket()
		if err != nil {
			return err
		}

		loginStart, loginStartNew, err := login.UnmarshalServerBoundLoginStart(session.loginPacket)
		if err != nil {
			return err
		}

		if reflect.ValueOf(loginStartNew).IsZero() {
			session.username = string(loginStart.Name)
		} else {
			if loginStartNew.HasSigData {
				session.HasSigData = true
				session.Timestamp = loginStartNew.Timestamp
				session.PublicKey = loginStartNew.PublicKey
				session.Signature = loginStartNew.Signature
			}
			session.username = string(loginStartNew.Name)
		}

		if Config.GeoIPenabled {
			err := gateway.geoCheck(conn, &session)
			if err != nil {
				return err
			}

			if Config.MojangAPIenabled && !gateway.underAttack {
				err := gateway.usernameCheck(conn, &session)
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
		if Config.GeoIPenabled {
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

	if Config.GeoIPenabled {
		record, err := gateway.db.Country(net.ParseIP(session.ip))
		session.country = record.Country.IsoCode
		if err != nil {
			log.Printf("[i] failed to lookup country for %s", session.connRemoteAddr)
		}
	}

	if !isLogin {
		_, err := conn.ReadPacket()
		if err != nil {
			return err
		}

		err = conn.WritePacket(DefaultStatusResponse())
		if err != nil {
			return err
		}

		pingPacket, err := conn.ReadPacket()
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
		if gateway.underAttack {
			if contains(Config.GeoIPCountryWhitelist, session.country) {
				err = gateway.rdb.Set(ctx, "ip:"+session.ip, "half,"+session.country, time.Hour*24).Err()
				if err != nil {
					log.Println(err)
				}

				if Config.MojangAPIenabled {
					err := gateway.loginCheck(conn, session)
					if err != nil {
						return err
					}
				} else {
					handshakeCount.With(prometheus.Labels{"type": "cancelled", "host": session.serverAddress, "country": session.country}).Inc()

					err = conn.WritePacket(login.ClientBoundDisconnect{
						Reason: protocol.Chat(fmt.Sprintf("{\"text\":\"%s\"}", Config.RejoinMessage)),
					}.Marshal())
					if err != nil {
						return err
					}

					return errors.New("blocked for rejoin (geoip)")
				}
			}

			handshakeCount.With(prometheus.Labels{"type": "cancelled_ip", "host": session.serverAddress, "country": session.country}).Inc()

			err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
			if err != nil {
				log.Println(err)
			}
			return errors.New("blocked because ip " + session.country)

		}
		if contains(Config.GeoIPCountryWhitelist, session.country) {
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
		results := strings.Split(result, ",")
		session.country = results[1]
		if gateway.underAttack {
			if results[0] == "false" {
				err := conn.Close()
				if err != nil {
					return err
				}
				handshakeCount.With(prometheus.Labels{"type": "cancelled_ip", "host": session.serverAddress, "country": session.country}).Inc()
				gateway.rdb.TTL(ctx, "ip:"+session.ip).SetVal(time.Hour * 12)
				return errors.New("blocked because ip cached as false")
			}
			if Config.MojangAPIenabled {
				err := gateway.loginCheck(conn, session)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (gateway *Gateway) usernameCheck(conn Conn, session *Session) error {
	//TODO retire
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
		err = gateway.rdb.Set(ctx, "ip:"+session.ip, "true,"+session.country, time.Hour*24).Err()
		if err != nil {
			log.Println(err)
		}
	}
	return nil
}

func (gateway *Gateway) loginCheck(conn Conn, session *Session) error {
	result, err := gateway.rdb.Get(ctx, "ip:"+session.ip).Result()
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

		encryptionResponse, err := conn.ReadPacket()
		if err != nil {
			handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
			err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
			return errors.New("invalid encryption response")
		}

		encryptionRes, encryptionResNew, err := login.UnmarshalServerBoundEncryptionResponse(encryptionResponse, session.ProtocolVersion)
		if err != nil {
			handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
			err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
			return errors.New("invalid encryptionResponse")
		}

		var decryptedSharedSecret []byte
		if !reflect.ValueOf(encryptionResNew).IsZero() {
			decryptedSharedSecret, err = gateway.privateKey.Decrypt(rand.Reader, encryptionResNew.SharedSecret, nil)
			if err != nil {
				handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
				err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
				return errors.New("failed to decrypt shared secret")
			}
			//TODO check signature and salt
		} else {
			decryptedVerifyToken, err := gateway.privateKey.Decrypt(rand.Reader, encryptionRes.VerifyToken, nil)
			if err != nil {
				handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
				err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
				return errors.New("failed to decrypt verify token")
			}

			if !bytes.Equal(decryptedVerifyToken, verifyToken) {
				handshakeCount.With(prometheus.Labels{"type": "cancelled_encryption", "host": session.serverAddress, "country": session.country}).Inc()
				err = gateway.rdb.Set(ctx, "ip:"+session.ip, "false,"+session.country, time.Hour*12).Err()
				return errors.New("invalid verify token")
			}

			decryptedSharedSecret, err = gateway.privateKey.Decrypt(rand.Reader, encryptionRes.SharedSecret, nil)
			if err != nil {
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

		err = conn.WritePacket(login.ClientBoundDisconnect{
			Reason: protocol.Chat(fmt.Sprintf("{\"text\":\"%s\"}", Config.RejoinMessage)),
		}.Marshal())
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
	if gateway.connections >= Config.ConnectionTreshold {
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
