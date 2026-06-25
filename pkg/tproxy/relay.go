package tproxy

import (
	"io"
	"net"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
)

// TCPRelay forwards data via SOCKS5 proxy to Xray/sing-box.
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

// Relay connects to SOCKS5 proxy and relays bidirectionally.
func (r *TCPRelay) Relay(inbound net.Conn, origAddr *net.TCPAddr) error {
	outbound, err := net.DialTimeout("tcp", r.socksAddr, r.timeout)
	if err != nil {
		return err
	}

	// SOCKS5 handshake: no auth
	_, err = outbound.Write([]byte{5, 1, 0})
	if err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(outbound, reply); err != nil {
		return err
	}

	// SOCKS5 connect to original destination
	host := origAddr.IP.To4()
	port := uint16(origAddr.Port)
	req := []byte{5, 1, 0, 1, host[0], host[1], host[2], host[3], byte(port >> 8), byte(port)}
	_, err = outbound.Write(req)
	if err != nil {
		return err
	}
	resp := make([]byte, 10)
	if _, err = io.ReadFull(outbound, resp); err != nil {
		return err
	}

	log.Debug("relay started", map[string]interface{}{
		"src": inbound.RemoteAddr().String(),
		"dst": origAddr.String(),
		"via": r.socksAddr,
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
