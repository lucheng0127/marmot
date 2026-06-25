// UDP TProxy — Phase 3.10
// Uses IP_TRANSPARENT + IP_RECVORIGDSTADDR to intercept UDP traffic.
// Sessions are tracked by (srcIP, srcPort, dstIP, dstPort) and GC'd by timeout.
package tproxy

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/lucheng0127/marmot/pkg/conntrack"
	"github.com/lucheng0127/marmot/pkg/log"
)

// UDPListener handles transparent UDP proxy.
type UDPListener struct {
	addr      string
	decider   Decider
	cache     FlowCacheWriter
	conn      net.PacketConn
	relayAddr string
	sessions  map[udpSessionKey]*udpSession
	mu        sync.Mutex
	done      chan struct{}
}

type udpSessionKey struct {
	SrcIP   [4]byte
	SrcPort uint16
	DstIP   [4]byte
	DstPort uint16
}

type udpSession struct {
	clientAddr *net.UDPAddr
	outbound   *net.UDPConn
	created    time.Time
	lastActive time.Time
	tag        string
}

func NewUDPListener(addr string, decider Decider, cache FlowCacheWriter, relayAddr string) *UDPListener {
	return &UDPListener{
		addr:      addr,
		decider:   decider,
		cache:     cache,
		relayAddr: relayAddr,
		sessions:  make(map[udpSessionKey]*udpSession),
		done:      make(chan struct{}),
	}
}

func (l *UDPListener) Start() error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_RECVORIGDSTADDR, 1)
			})
		},
	}
	var err error
	l.conn, err = lc.ListenPacket(nil, "udp", l.addr)
	if err != nil {
		return fmt.Errorf("udp tproxy listen %s: %w", l.addr, err)
	}
	log.Info("UDP TProxy listening", map[string]interface{}{"addr": l.addr})
	go l.readLoop()
	go l.gcLoop()
	return nil
}

func (l *UDPListener) Close() error {
	close(l.done)
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *UDPListener) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-l.done:
			return
		default:
		}
		n, origAddr, clientAddr, err := readUDP(l.conn, buf)
		if err != nil {
			log.Error("udp read error", map[string]interface{}{"error": err.Error()})
			continue
		}
		if clientAddr == nil || origAddr == nil {
			continue
		}

		key := sessionKey(clientAddr, origAddr)
		l.mu.Lock()
		sess, exists := l.sessions[key]
		if !exists {
			// New UDP session — write to cache, dial outbound
			cacheKey := conntrack.CacheKey{
				DstIP:   ipToUint32BE(origAddr.IP),
				DstPort: htons(uint16(origAddr.Port)),
				Protocol: 17,
			}
			var decision uint8
			if l.cache != nil {
				if d, _, hit := l.cacheLookup(cacheKey); hit {
					decision = uint8(d)
					log.Debug("UDP Decision Cache HIT", map[string]interface{}{
						"target": origAddr.String(),
					})
				}
			}
			if decision == 0 && l.decider != nil {
				flowKey := FlowKey{
					SrcIP:   ipToUint32BE(clientAddr.IP),
					DstIP:   ipToUint32BE(origAddr.IP),
					SrcPort: htons(uint16(clientAddr.Port)),
					DstPort: htons(uint16(origAddr.Port)),
					Protocol: 17,
				}
				decision = uint8(l.decider.Decide(flowKey))
			}
			if l.cache != nil {
				l.cache.Insert(cacheKey, decision)
			}

			// Dial outbound (Xray or sing-box)
			outbound, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10800})
			if err != nil {
				log.Error("udp dial outbound", map[string]interface{}{"error": err.Error()})
				l.mu.Unlock()
				continue
			}
			sess = &udpSession{
				clientAddr: clientAddr,
				outbound:   outbound,
				created:    time.Now(),
				lastActive: time.Now(),
			}
			l.sessions[key] = sess
			// Start reverse reader
			go l.reverseRelay(key, sess)
		}
		sess.lastActive = time.Now()
		l.mu.Unlock()

		// Forward data to outbound
		if _, err := sess.outbound.Write(buf[:n]); err != nil {
			log.Warn("udp relay write error", map[string]interface{}{"error": err.Error()})
		}
	}
}

func (l *UDPListener) reverseRelay(key udpSessionKey, sess *udpSession) {
	buf := make([]byte, 65535)
	for {
		_ = sess.outbound.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := sess.outbound.Read(buf)
		if err != nil {
			l.mu.Lock()
			sess.outbound.Close()
			delete(l.sessions, key)
			l.mu.Unlock()
			return
		}
		if _, err := l.conn.WriteTo(buf[:n], sess.clientAddr); err != nil {
			return
		}
	}
}

func (l *UDPListener) gcLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			now := time.Now()
			for key, sess := range l.sessions {
				if now.Sub(sess.lastActive) > 120*time.Second {
					sess.outbound.Close()
					delete(l.sessions, key)
				}
			}
			l.mu.Unlock()
		case <-l.done:
			return
		}
	}
}

func (l *UDPListener) cacheLookup(key conntrack.CacheKey) (conntrack.Decision, uint64, bool) {
	type lookupper interface {
		Lookup(conntrack.CacheKey) (conntrack.Decision, uint64, bool)
	}
	if cl, ok := l.cache.(lookupper); ok {
		return cl.Lookup(key)
	}
	return 0, 0, false
}

// IP_RECVORIGDSTADDR = 20 on Linux
const IP_RECVORIGDSTADDR = 20

// readUDP reads from a UDP PacketConn and returns the data,
// the original destination address, and the client address.
func readUDP(conn net.PacketConn, buf []byte) (int, *net.UDPAddr, *net.UDPAddr, error) {
	// Standard ReadFrom only returns client address — not original dest.
	// For transparent proxy, we use SO_ORIGINAL_DST or IP_RECVORIGDSTADDR.
	// On modern kernels, the original destination is returned in the oob data.
	oob := make([]byte, 1024)
	n, oobn, _, addr, err := conn.(*net.UDPConn).ReadMsgUDP(buf, oob)
	if err != nil {
		return 0, nil, nil, err
	}
	clientAddr := addr

	// Parse cmsg for original destination
	var origAddr *net.UDPAddr
	if oobn > 0 {
		cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err == nil {
			for _, cm := range cmsgs {
				if cm.Header.Level == syscall.IPPROTO_IP &&
					cm.Header.Type == IP_RECVORIGDSTADDR {
					origAddr = parseOrigDstAddr(cm.Data)
				}
			}
		}
	}
	if origAddr == nil {
		// Fallback: use dest address
		origAddr = clientAddr
	}
	return n, origAddr, clientAddr, nil
}

func parseOrigDstAddr(data []byte) *net.UDPAddr {
	if len(data) < 8 {
		return nil
	}
	// struct sockaddr_in: family(2), port(2), addr(4), zero(8)
	family := uint16(data[0]) | uint16(data[1])<<8
	if family != syscall.AF_INET {
		return nil
	}
	port := int(data[2])<<8 | int(data[3])
	ip := net.IPv4(data[4], data[5], data[6], data[7])
	return &net.UDPAddr{IP: ip, Port: port}
}

func sessionKey(client, orig *net.UDPAddr) udpSessionKey {
	key := udpSessionKey{
		SrcPort: htons(uint16(client.Port)),
		DstPort: htons(uint16(orig.Port)),
	}
	copy(key.SrcIP[:], client.IP.To4())
	copy(key.DstIP[:], orig.IP.To4())
	return key
}

func ipToUint32BE(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) |
		(uint32(ip[2]) << 8) | uint32(ip[3])
}
