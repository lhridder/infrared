package infrared

import (
	"errors"
	"github.com/haveachin/infrared/callback"
	"github.com/haveachin/infrared/protocol/handshaking"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

var (
	handshakeCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "infrared_handshakes",
		Help: "The total number of handshakes made to each proxy by type",
	}, []string{"type", "host"})
	//TODO make variable
	underAttack = true
)

type Gateway struct {
	listeners            sync.Map
	proxies              sync.Map
	closed               chan bool
	wg                   sync.WaitGroup
	receiveProxyProtocol bool
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

	// Disabled because since the host is taken from the packet anyway
	//handshakeCount.WithLabelValues("login", proxy.DomainName())
	//handshakeCount.WithLabelValues("status", proxy.DomainName())

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
			// TODO: Refactor this; it feels hacky
			if err.Error() == "use of closed network connection" {
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

func (gateway *Gateway) serve(conn Conn, addr string) error {
	connRemoteAddr := conn.RemoteAddr()
	if gateway.receiveProxyProtocol {
		header, err := proxyproto.Read(conn.Reader())
		if err != nil {
			return err
		}
		connRemoteAddr = header.SourceAddr
	}

	pk, err := conn.PeekPacket()
	if err != nil {
		return err
	}

	hs, err := handshaking.UnmarshalServerBoundHandshake(pk)
	if err != nil {
		return err
	}

	country := ""
	if GeoIPenabled && underAttack {
		ip, _, _ := net.SplitHostPort(connRemoteAddr.String())
		record, err := db.Country(net.ParseIP(ip))
		if err != nil {
			log.Printf("[i] failed to lookup country for %s", connRemoteAddr)
		}
		if contains(CountryWhitelist, record.Country.IsoCode) {
			//TODO further checks
		} else {
			err := conn.Close()
			if err != nil {
				log.Println(err)
			}
			log.Printf("[i] Blocked %s from joining because of country %s", connRemoteAddr, country)
			return nil
		}
	}

	serverAddress := hs.ParseServerAddress()
	host := strings.ToLower(strings.Split(serverAddress, "###")[0])
	if hs.IsLoginRequest() {
		handshakeCount.With(prometheus.Labels{"type": "login", "host": host}).Inc()
	} else if hs.IsStatusRequest() {
		handshakeCount.With(prometheus.Labels{"type": "status", "host": host}).Inc()
	}

	proxyUID := proxyUID(serverAddress, addr)

	log.Printf("[i] %s requests proxy with UID %s", connRemoteAddr, proxyUID)
	v, ok := gateway.proxies.Load(proxyUID)
	if !ok {
		if hs.IsStatusRequest() {
			conn.ReadPacket()
			conn.WritePacket(DefaultStatusResponse())
			pingPk, _ := conn.ReadPacket()
			conn.WritePacket(pingPk)
		}

		// Client send an invalid address/port; we don't have a v for that address
		return errors.New("no proxy with uid " + proxyUID)
	}
	proxy := v.(*Proxy)

	if err := proxy.handleConn(conn, connRemoteAddr); err != nil {
		proxy.CallbackLogger().LogEvent(callback.ErrorEvent{
			Error:    err.Error(),
			ProxyUID: proxyUID,
		})
		return err
	}
	return nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
