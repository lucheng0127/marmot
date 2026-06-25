package tproxy

import (
	"io"
	"net"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
)

// DialFunc connects to an address (used by relay to connect through proxy engine).
type DialFunc func(network, addr string) (net.Conn, error)

// TCPRelay forwards data between the TProxy inbound and the proxy engine.
// Uses DialFunc instead of SOCKS5 — no external process needed.
type TCPRelay struct {
	dial    DialFunc
	timeout time.Duration
}

func NewTCPRelay(dial DialFunc, timeout time.Duration) *TCPRelay {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &TCPRelay{dial: dial, timeout: timeout}
}

// Relay connects to the original destination through the proxy engine
// and copies data bidirectionally.
func (r *TCPRelay) Relay(inbound net.Conn, origAddr *net.TCPAddr) error {
	// Dial through engine
	outbound, err := r.dial("tcp", origAddr.String())
	if err != nil {
		return err
	}

	log.Debug("relay started", map[string]interface{}{
		"src": inbound.RemoteAddr().String(),
		"dst": origAddr.String(),
	})

	// Bidirectional copy with total timeout
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(outbound, inbound)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(inbound, outbound)
		errCh <- err
	}()

	select {
	case <-errCh:
	case <-time.After(r.timeout):
	}
	_ = outbound.Close()
	_ = inbound.Close()
	return nil
}
