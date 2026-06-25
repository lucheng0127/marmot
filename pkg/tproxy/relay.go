package tproxy

import (
	"io"
	"net"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
)

// idleTimeoutConn wraps a net.Conn with idle read/write deadlines.
type idleTimeoutConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleTimeoutConn) Read(b []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *idleTimeoutConn) Write(b []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// copyWithIdleTimeout copies bidirectionally with idle + total timeout.
func copyWithIdleTimeout(inbound, outbound net.Conn, idle, total time.Duration) {
	wrapIn := &idleTimeoutConn{Conn: inbound, idle: idle}
	wrapOut := &idleTimeoutConn{Conn: outbound, idle: idle}
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(wrapOut, wrapIn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(wrapIn, wrapOut)
		errCh <- err
	}()
	select {
	case <-errCh:
	case <-time.After(total):
	}
	_ = inbound.Close()
	_ = outbound.Close()
}

// DialFunc connects through the proxy engine.
type DialFunc func(network, addr string) (net.Conn, error)

// TCPRelay forwards data via SOCKS5 proxy.
type TCPRelay struct {
	socksAddr string
	timeout   time.Duration
}

func NewTCPRelay(socksAddr string, timeout time.Duration) *TCPRelay {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &TCPRelay{socksAddr: socksAddr, timeout: timeout}
}

func (r *TCPRelay) Relay(inbound net.Conn, origAddr *net.TCPAddr) error {
	outbound, err := net.DialTimeout("tcp", r.socksAddr, r.timeout)
	if err != nil {
		return err
	}
	// SOCKS5 no-auth handshake
	if _, err = outbound.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(outbound, reply); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != 0 {
		return err
	}
	// SOCKS5 CONNECT
	buf := make([]byte, 10)
	buf[0], buf[1], buf[2], buf[3] = 5, 1, 0, 1
	copy(buf[4:8], origAddr.IP.To4())
	buf[8] = byte(origAddr.Port >> 8)
	buf[9] = byte(origAddr.Port)
	if _, err = outbound.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 10)
	if _, err = io.ReadFull(outbound, resp); err != nil {
		return err
	}
	if resp[0] != 5 || resp[1] != 0 {
		return err
	}
	log.Debug("relay started", map[string]interface{}{
		"src": inbound.RemoteAddr().String(), "dst": origAddr.String(), "proxy": r.socksAddr,
	})
	copyWithIdleTimeout(inbound, outbound, 5*time.Second, r.timeout)
	return nil
}

// TCPRelay2 forwards data using a DialFunc (engine-based relay).
type TCPRelay2 struct {
	dial    DialFunc
	timeout time.Duration
}

func NewTCPRelay2(dial DialFunc, timeout time.Duration) *TCPRelay2 {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &TCPRelay2{dial: dial, timeout: timeout}
}

func (r *TCPRelay2) Relay(inbound net.Conn, origAddr *net.TCPAddr) error {
	outbound, err := r.dial("tcp", origAddr.String())
	if err != nil {
		return err
	}
	log.Debug("relay started", map[string]interface{}{
		"src": inbound.RemoteAddr().String(), "dst": origAddr.String(),
	})
	copyWithIdleTimeout(inbound, outbound, 5*time.Second, r.timeout)
	return nil
}
