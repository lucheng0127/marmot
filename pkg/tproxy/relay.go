package tproxy

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
)

// TCPRelay forwards data between the TProxy inbound connection and
// the proxy outbound (sing-box or Xray dokodemo-door).
//
// Phase 3 implementation: simple bidirectional io.Copy.
// Phase 5 may add connection pooling, multiplexing, or zero-copy.
type TCPRelay struct {
	outboundAddr string // e.g. "127.0.0.1:10800" for Xray
	timeout      time.Duration
}

func NewTCPRelay(outboundAddr string, timeout time.Duration) *TCPRelay {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &TCPRelay{
		outboundAddr: outboundAddr,
		timeout:      timeout,
	}
}

// Relay copies data between the inbound client connection and
// the outbound proxy engine.
func (r *TCPRelay) Relay(inbound net.Conn, origAddr *net.TCPAddr) error {
	// Dial outbound
	outbound, err := net.DialTimeout("tcp", r.outboundAddr, r.timeout)
	if err != nil {
		return fmt.Errorf("dial outbound %s: %w", r.outboundAddr, err)
	}

	log.Debug("relay started", map[string]interface{}{
		"src":   inbound.RemoteAddr().String(),
		"dst":   origAddr.String(),
		"via":   r.outboundAddr,
	})

	// Bidirectional copy
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(outbound, inbound)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(inbound, outbound)
		errCh <- err
	}()

	// Wait for one side to finish
	err = <-errCh
	_ = outbound.Close()
	_ = inbound.Close()

	if err != nil && err != io.EOF {
		return fmt.Errorf("relay error: %w", err)
	}
	return nil
}
