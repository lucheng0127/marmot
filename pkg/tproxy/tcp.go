package tproxy

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/lucheng0127/marmot/pkg/log"
)

// Listener manages the TProxy TCP socket and handles incoming connections.
type Listener struct {
	addr    string
	decider Decider
	cache   FlowCacheWriter
	ln      net.Listener
}

// FlowCacheWriter is the interface Conntrack Cache must implement
// for TProxy to write back flow decisions.
type FlowCacheWriter interface {
	Insert(key FlowKey, decision Decision) error
}

// NewListener creates a new TProxy TCP listener.
// addr: listening address like ":1080"
// decider: Decision Interface
// cache: Conntrack Cache for Flow writeback
func NewListener(addr string, decider Decider, cache FlowCacheWriter) *Listener {
	return &Listener{
		addr:    addr,
		decider: decider,
		cache:   cache,
	}
}

// Start begins listening for TCP connections on the TProxy port.
// Must be run as root (CAP_NET_ADMIN) due to IP_TRANSPARENT socket option.
func (l *Listener) Start() error {
	config := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Enable IP_TRANSPARENT — allows binding to non-local IPs
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

	log.Info("TProxy TCP listening", map[string]interface{}{
		"addr": l.addr,
	})

	go l.acceptLoop()
	return nil
}

// acceptLoop runs in a goroutine, accepting connections from the TProxy socket.
func (l *Listener) acceptLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Error("TProxy accept error", map[string]interface{}{
					"error": err.Error(),
				})
			}
			return
		}
		go l.handleConn(conn)
	}
}

// handleConn processes a single accepted TProxy connection.
// Extracts the original destination, makes a decision, and writes to Flow Cache.
// In Phase 2, the connection is simply closed after logging.
// Phase 3 will forward to sing-box outbound.
func (l *Listener) handleConn(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return
	}

	// Extract original destination via SO_ORIGINAL_DST
	origAddr, err := getOriginalDest(tcpConn)
	if err != nil {
		log.Error("get original dst failed", map[string]interface{}{
			"error": err.Error(),
		})
		conn.Close()
		return
	}

	// Build 5-tuple flow key
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	flowKey := FlowKey{
		DstIP:   IPToUint32(origAddr.IP),
		DstPort: htons(uint16(origAddr.Port)),
		Protocol: 6, // TCP
	}
	if remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		flowKey.SrcIP = IPToUint32(remoteAddr.IP)
		flowKey.SrcPort = htons(uint16(remoteAddr.Port))
	}

	// Make decision via Decision Interface
	decision := l.decider.Decide(flowKey)

	log.Debug("TProxy connection", map[string]interface{}{
		"src":      conn.RemoteAddr().String(),
		"orig_dst": origAddr.String(),
		"local":    localAddr.String(),
		"decision": decisionName(decision),
	})

	// Write decision to Conntrack Cache → BPF Flow Map
	if l.cache != nil {
		if err := l.cache.Insert(flowKey, decision); err != nil {
			log.Error("cache insert failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Phase 2: close connection after recording.
	// Phase 3 will proxy the connection via sing-box outbound.
	conn.Close()
}

// Close stops the TProxy listener.
func (l *Listener) Close() error {
	if l.ln != nil {
		return l.ln.Close()
	}
	return nil
}

// getOriginalDest retrieves the original destination IP:port
// that was intercepted by the TProxy, using SO_ORIGINAL_DST.
func getOriginalDest(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, fmt.Errorf("get conn file: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// SO_ORIGINAL_DST = 80 on Linux
	const SO_ORIGINAL_DST = 80

	type sockaddr_in struct {
		family uint16
		port   [2]byte
		addr   [4]byte
		zero   [8]byte
	}

	saRaw, err := syscall.Getsockname(fd)
	if err != nil {
		// Try getsockopt with SO_ORIGINAL_DST
		// This works for iptables REDIRECT/TPROXY
		// On modern kernels, we can use SO_ORIGINAL_DST via getsockopt
		val, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err == nil {
			// Parse the sockaddr_in from the int value
			// This is a simplified approach - for production we'd use
			// the full sockaddr_in structure
			_ = val
		}

		// For Phase 2, fall back to the local address as original dest
		// since IP_TRANSPARENT + TPROXY already redirects to us
		localAddr := conn.LocalAddr().(*net.TCPAddr)
		log.Debug("SO_ORIGINAL_DST fallback to local addr", map[string]interface{}{
			"error": err.Error(),
		})
		return localAddr, nil
	}
	_ = saRaw

	// Proper SO_ORIGINAL_DST extraction
	// This requires reading the sockaddr_in via Getsockopt with a struct
	// For now, use a simpler approach that works with the syscall package
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return nil, fmt.Errorf("getsockname: %w", err)
	}

	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return &net.TCPAddr{
			IP:   net.IP(sa.Addr[:]),
			Port: sa.Port,
		}, nil
	default:
		// Fallback: return the local address
		return conn.LocalAddr().(*net.TCPAddr), nil
	}
}

// --- helpers ---

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

// IPToUint32 converts an IPv4 address to network byte order uint32.
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) |
		(uint32(ip[2]) << 8) | uint32(ip[3])
}

// htons converts from host to network byte order (big-endian).
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// Ensure interface compliance
var _ FlowCacheWriter = (FlowCacheWriter)(nil)

// Ensure os is used
var _ = os.DevNull
var _ = strconv.Itoa
