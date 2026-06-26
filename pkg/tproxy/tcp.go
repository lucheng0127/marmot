package tproxy

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lucheng0127/marmot/pkg/conntrack"
	"github.com/lucheng0127/marmot/pkg/log"
)

// FlowCacheWriter is the interface the Decision Cache must implement.
type FlowCacheWriter interface {
	Insert(key conntrack.CacheKey, decision uint8)
}

// Listener manages the TProxy TCP socket and handles incoming connections.
type Listener struct {
	addr      string
	decider   Decider
	cache     FlowCacheWriter
	ln        net.Listener
	relayAddr *string  // SOCKS5 relay address (e.g. "127.0.0.1:10800")
	dial      DialFunc // sing-box dialer (used when relayAddr is nil)
}

// NewListener creates a new TProxy TCP listener.
// If dial is nil and relayAddr is empty, traffic is dropped after logging.
func NewListener(addr string, decider Decider, cache FlowCacheWriter, relayAddrOrDial ...interface{}) *Listener {
	l := &Listener{
		addr:    addr,
		decider: decider,
		cache:   cache,
	}
	for _, arg := range relayAddrOrDial {
		switch v := arg.(type) {
		case string:
			if v != "" {
				l.relayAddr = &v
			}
		case DialFunc:
			l.dial = v
		}
	}
	return l
}
func (l *Listener) Start() error {
	config := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP,
					syscall.IP_TRANSPARENT, 1); err != nil {
					log.Error("set IP_TRANSPARENT failed", map[string]interface{}{
						"error": err.Error(),
					})
				}
			})
		},
	}
	var err error
	l.ln, err = config.Listen(nil, "tcp", l.addr)
	if err != nil {
		return fmt.Errorf("tproxy listen %s: %w", l.addr, err)
	}
	log.Info("TProxy TCP listening", map[string]interface{}{"addr": l.addr})
	go l.acceptLoop()
	return nil
}

func (l *Listener) acceptLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Error("TProxy accept error", map[string]interface{}{"error": err.Error()})
			}
			return
		}
		go l.handleConn(conn)
	}
}

func (l *Listener) handleConn(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return
	}
	origAddr, err := getOriginalDest(tcpConn)
	if err != nil {
		log.Error("get original dst failed", map[string]interface{}{"error": err.Error()})
		conn.Close()
		return
	}

	// Decision Cache lookup
	cacheKey := conntrack.CacheKey{
		DstIP:   IPToUint32(origAddr.IP),
		DstPort: htons(uint16(origAddr.Port)),
		Protocol: 6,
	}
	var decision uint8
	if l.cache != nil {
		type cacheLookupper interface {
			Lookup(conntrack.CacheKey) (conntrack.Decision, uint64, bool)
		}
		if cl, ok := l.cache.(cacheLookupper); ok {
			if d, _, hit := cl.Lookup(cacheKey); hit {
				decision = uint8(d)
				log.Debug("Decision Cache HIT", map[string]interface{}{
					"target": origAddr.String(),
				})
			}
		}
	}

	if decision == 0 && l.decider != nil {
		flowKey := FlowKey{
			DstIP:   IPToUint32(origAddr.IP),
			DstPort: htons(uint16(origAddr.Port)),
			Protocol: 6,
		}
		if remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			flowKey.SrcIP = IPToUint32(remoteAddr.IP)
			flowKey.SrcPort = htons(uint16(remoteAddr.Port))
		}
		decision = uint8(l.decider.Decide(flowKey))
	}

	log.Debug("TProxy connection", map[string]interface{}{
		"src":      conn.RemoteAddr().String(),
		"orig_dst": origAddr.String(),
		"decision": decisionName(Decision(decision)),
	})

	if l.cache != nil {
		l.cache.Insert(cacheKey, uint8(decision))
	}

	// Relay: SOCKS5 via Xray, or sing-box dialer fallback
	if decision == uint8(DecisionProxy) && l.relayAddr != nil {
		relay := NewTCPRelay(*l.relayAddr, 30*time.Second)
		if err := relay.Relay(conn, origAddr); err != nil {
			log.Error("relay error", map[string]interface{}{
				"error": err.Error(),
				"src":   conn.RemoteAddr().String(),
				"dst":   origAddr.String(),
			})
		}
	} else if decision == uint8(DecisionProxy) && l.dial != nil {
		relay := NewTCPRelay2(l.dial, 30*time.Second)
		if err := relay.Relay(conn, origAddr); err != nil {
			log.Error("relay error", map[string]interface{}{
				"error": err.Error(),
				"src":   conn.RemoteAddr().String(),
				"dst":   origAddr.String(),
			})
		}
	} else if decision == uint8(DecisionDirect) && l.dial != nil {
		directDial := func(network, addr string) (net.Conn, string, error) {
			conn, err := net.DialTimeout(network, addr, 10*time.Second)
			return conn, "direct", err
		}
		relay := NewTCPRelay2(directDial, 30*time.Second)
		if err := relay.Relay(conn, origAddr); err != nil {
			log.Debug("direct relay end", map[string]interface{}{"src": conn.RemoteAddr().String(), "dst": origAddr.String()})
		}
	} else {
		conn.Close()
	}
}

func (l *Listener) Close() error {
	if l.ln != nil {
		return l.ln.Close()
	}
	return nil
}

func getOriginalDest(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, fmt.Errorf("get conn file: %w", err)
	}
	defer file.Close()
	fd := int(file.Fd())
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return conn.LocalAddr().(*net.TCPAddr), nil
	}
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return &net.TCPAddr{
			IP:   net.IP(sa.Addr[:]),
			Port: sa.Port,
		}, nil
	default:
		return conn.LocalAddr().(*net.TCPAddr), nil
	}
}

func decisionName(d Decision) string {
	switch d {
	case DecisionDirect:
		return "direct"
	case DecisionProxy:
		return "proxy"
	default:
		return fmt.Sprintf("unknown(%d)", d)
	}
}

func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) |
		(uint32(ip[2]) << 8) | uint32(ip[3])
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

var _ = os.DevNull
var _ = strconv.Itoa
