package infrared

import (
	"fmt"
	"github.com/haveachin/infrared/protocol"
	"github.com/haveachin/infrared/protocol/handshaking"
	"github.com/haveachin/infrared/protocol/login"
	"github.com/haveachin/infrared/protocol/status"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	playersConnected = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "infrared_connected",
		Help: "The total number of connected players",
	}, []string{"host"})
)

func proxyUID(domain, addr string) string {
	return fmt.Sprintf("%s@%s", strings.ToLower(domain), addr)
}

type Proxy struct {
	Config *ProxyConfig

	cancelTimeoutFunc func()
	players           map[Conn]string
	mu                sync.Mutex

	cacheTime     time.Time
	cacheResponse protocol.Packet
}

func (proxy *Proxy) DomainNames() []string {
	proxy.Config.RLock()
	defer proxy.Config.RUnlock()
	return proxy.Config.DomainNames
}

func (proxy *Proxy) DomainName() string {
	proxy.Config.RLock()
	defer proxy.Config.RUnlock()
	return proxy.Config.DomainNames[0]
}

func (proxy *Proxy) ListenTo() string {
	proxy.Config.RLock()
	defer proxy.Config.RUnlock()
	return proxy.Config.ListenTo
}

func (proxy *Proxy) ProxyTo() string {
	proxy.Config.RLock()
	defer proxy.Config.RUnlock()
	return proxy.Config.ProxyTo
}

func (proxy *Proxy) Dialer() (*Dialer, error) {
	proxy.Config.RLock()
	defer proxy.Config.RUnlock()
	return proxy.Config.Dialer()
}

func (proxy *Proxy) DisconnectMessage() string {
	proxy.Config.RLock()
	defer proxy.Config.RUnlock()
	return proxy.Config.DisconnectMessage
}

func (proxy *Proxy) IsOnlineStatusConfigured() bool {
	proxy.Config.Lock()
	defer proxy.Config.Unlock()
	return proxy.Config.OnlineStatus.ProtocolNumber != 0
}

func (proxy *Proxy) OnlineStatusPacket() (protocol.Packet, error) {
	proxy.Config.Lock()
	defer proxy.Config.Unlock()
	return proxy.Config.OnlineStatus.StatusResponsePacket()
}

func (proxy *Proxy) OfflineStatusPacket() (protocol.Packet, error) {
	proxy.Config.Lock()
	defer proxy.Config.Unlock()
	return proxy.Config.OfflineStatus.StatusResponsePacket()
}

func (proxy *Proxy) Timeout() time.Duration {
	proxy.Config.RLock()
	defer proxy.Config.RUnlock()
	return time.Millisecond * time.Duration(proxy.Config.Timeout)
}

func (proxy *Proxy) ProxyProtocol() bool {
	proxy.Config.RLock()
	defer proxy.Config.RUnlock()
	return proxy.Config.ProxyProtocol
}

func (proxy *Proxy) RealIP() bool {
	proxy.Config.RLock()
	defer proxy.Config.RUnlock()
	return proxy.Config.RealIP
}

func (proxy *Proxy) UID() string {
	return proxyUID(proxy.DomainName(), proxy.ListenTo())
}

func (proxy *Proxy) UIDs() []string {
	uids := []string{}
	for _, domain := range proxy.DomainNames() {
		uid := proxyUID(domain, proxy.ListenTo())
		uids = append(uids, uid)
	}
	return uids
}

func (proxy *Proxy) addPlayer(conn Conn, username string) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.players == nil {
		proxy.players = map[Conn]string{}
	}
	proxy.players[conn] = username
}

func (proxy *Proxy) removePlayer(conn Conn) int {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.players == nil {
		proxy.players = map[Conn]string{}
		return 0
	}
	delete(proxy.players, conn)
	return len(proxy.players)
}

func (proxy *Proxy) handleConn(conn Conn, connRemoteAddr net.Addr, handshakePacket protocol.Packet, loginPacket protocol.Packet) error {
	hs, err := handshaking.UnmarshalServerBoundHandshake(handshakePacket)
	if err != nil {
		return err
	}

	proxyDomain := proxy.DomainName()
	proxyTo := proxy.ProxyTo()
	proxyUID := proxy.UID()

	if hs.IsStatusRequest() {
		if proxy.IsOnlineStatusConfigured() {
			return proxy.handleStatusRequest(conn, true)
		}
		if proxy.cacheTime.IsZero() || time.Now().Sub(proxy.cacheTime) > 30*time.Second {
			log.Printf("[i] Updating cache for %s", proxyUID)
			dialer, err := proxy.Dialer()
			if err != nil {
				return err
			}

			rconn, err := dialer.Dial(proxyTo)
			if err != nil {
				log.Printf("[i] %s did not respond to ping; is the target offline?", proxyTo)
				return proxy.handleStatusRequest(conn, false)
			}

			if proxy.RealIP() {
				hs.UpgradeToRealIP(connRemoteAddr, time.Now())
				handshakePacket = hs.Marshal()
			}

			if proxy.ProxyProtocol() {
				header := &proxyproto.Header{
					Version:           2,
					Command:           proxyproto.PROXY,
					TransportProtocol: proxyproto.TCPv4,
					SourceAddr:        connRemoteAddr,
					DestinationAddr:   rconn.RemoteAddr(),
				}

				if _, err = header.WriteTo(rconn); err != nil {
					return err
				}
			}

			_, portString, _ := net.SplitHostPort(proxyTo)
			port, err := strconv.ParseInt(portString, 10, 16)

			err = rconn.WritePacket(handshaking.ServerBoundHandshake{
				ProtocolVersion: hs.ProtocolVersion,
				ServerAddress:   protocol.String(proxy.DomainName()),
				ServerPort:      protocol.UnsignedShort(port),
				NextState:       1,
			}.Marshal())
			if err != nil {
				return err
			}

			err = rconn.WritePacket(status.ServerBoundRequest{}.Marshal())
			if err != nil {
				return err
			}

			clientboundResponse, err := rconn.ReadPacket()
			if err != nil {
				return err
			}
			_, err = status.UnmarshalClientBoundResponse(clientboundResponse)
			if err != nil {
				return err
			}

			proxy.cacheTime = time.Now()
			proxy.cacheResponse = clientboundResponse

			rconn.Close()
		}
		_, err := conn.ReadPacket()
		if err != nil {
			return err
		}

		err = conn.WritePacket(proxy.cacheResponse)
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

		log.Printf("[i] Sent %s cached response for %s", connRemoteAddr, proxyUID)
		return nil
	}

	dialer, err := proxy.Dialer()
	if err != nil {
		return err
	}

	rconn, err := dialer.Dial(proxyTo)
	if err != nil {
		log.Printf("[i] %s did not respond to ping; is the target offline?", proxyTo)
		return proxy.handleLoginRequest(conn)
	}
	defer rconn.Close()

	if proxy.ProxyProtocol() {
		header := &proxyproto.Header{
			Version:           2,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        connRemoteAddr,
			DestinationAddr:   rconn.RemoteAddr(),
		}

		if _, err = header.WriteTo(rconn); err != nil {
			return err
		}
	}

	if proxy.RealIP() {
		hs.UpgradeToRealIP(connRemoteAddr, time.Now())
		handshakePacket = hs.Marshal()
	}

	if err := rconn.WritePacket(handshakePacket); err != nil {
		return err
	}

	ls, err := login.UnmarshalServerBoundLoginStart(loginPacket)
	if err != nil {
		return err
	}
	username := string(ls.Name)
	err = rconn.WritePacket(loginPacket)
	if err != nil {
		return err
	}
	log.Printf("[i] %s with username %s connects through %s", connRemoteAddr, username, proxy.UID())
	proxy.addPlayer(conn, username)
	playersConnected.With(prometheus.Labels{"host": proxyDomain}).Inc()
	defer playersConnected.With(prometheus.Labels{"host": proxyDomain}).Dec()

	go pipe(rconn, conn)
	pipe(conn, rconn)
	return nil
}

func pipe(src, dst Conn) {
	buffer := make([]byte, 0xffff)

	for {
		n, err := src.Read(buffer)
		if err != nil {
			return
		}

		data := buffer[:n]

		_, err = dst.Write(data)
		if err != nil {
			return
		}
	}
}

func (proxy *Proxy) handleLoginRequest(conn Conn) error {
	packet, err := conn.ReadPacket()
	if err != nil {
		return err
	}

	loginStart, err := login.UnmarshalServerBoundLoginStart(packet)
	if err != nil {
		return err
	}

	message := proxy.DisconnectMessage()
	templates := map[string]string{
		"username":      string(loginStart.Name),
		"now":           time.Now().Format(time.RFC822),
		"remoteAddress": conn.LocalAddr().String(),
		"localAddress":  conn.LocalAddr().String(),
		"domain":        proxy.DomainName(),
		"proxyTo":       proxy.ProxyTo(),
		"listenTo":      proxy.ListenTo(),
	}

	for key, value := range templates {
		message = strings.Replace(message, fmt.Sprintf("{{%s}}", key), value, -1)
	}

	return conn.WritePacket(login.ClientBoundDisconnect{
		Reason: protocol.Chat(fmt.Sprintf("{\"text\":\"%s\"}", message)),
	}.Marshal())
}

func (proxy *Proxy) handleStatusRequest(conn Conn, online bool) error {
	// Read the request packet and send status response back
	_, err := conn.ReadPacket()
	if err != nil {
		return err
	}

	var responsePk protocol.Packet
	if online {
		responsePk, err = proxy.OnlineStatusPacket()
		if err != nil {
			return err
		}
	} else {
		responsePk, err = proxy.OfflineStatusPacket()
		if err != nil {
			return err
		}
	}

	if err := conn.WritePacket(responsePk); err != nil {
		return err
	}

	pingPk, err := conn.ReadPacket()
	if err != nil {
		return err
	}

	return conn.WritePacket(pingPk)
}
