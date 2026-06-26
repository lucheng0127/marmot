package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// UpstreamType defines the DNS upstream protocol.
type UpstreamType string

const (
	UpstreamUDP   UpstreamType = "udp"
	UpstreamTCP   UpstreamType = "tcp"
	UpstreamDoH   UpstreamType = "doh"
	UpstreamDoT   UpstreamType = "dot"
	UpstreamLocal UpstreamType = "local"
)

// UpstreamConfig describes a single DNS upstream server.
type UpstreamConfig struct {
	Type     UpstreamType `yaml:"type"`
	Address  string       `yaml:"address"`  // e.g. 8.8.8.8:53, https://dns.google/dns-query
	Timeout  time.Duration `yaml:"timeout"`
	Tag      string       `yaml:"tag"`      // for Rule Engine routing
}

// Forwarder sends DNS queries to upstream servers.
type Forwarder struct {
	config *UpstreamConfig
	client *http.Client // for DoH
	tlsCfg *tls.Config  // for DoT
}

func NewForwarder(cfg *UpstreamConfig) *Forwarder {
	f := &Forwarder{config: cfg}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	switch cfg.Type {
	case UpstreamDoH:
		f.client = &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	case UpstreamDoT:
		f.tlsCfg = &tls.Config{
			ServerName: hostFromAddr(cfg.Address),
		}
	}
	return f
}

// Exchange sends a DNS query to the upstream and returns the response.
func (f *Forwarder) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	switch f.config.Type {
	case UpstreamUDP, UpstreamTCP:
		return f.exchangeRaw(ctx, query)
	case UpstreamDoH:
		return f.exchangeDoH(ctx, query)
	case UpstreamDoT:
		return f.exchangeDoT(ctx, query)
	case UpstreamLocal:
		return nil, fmt.Errorf("local resolver not implemented")
	default:
		return nil, fmt.Errorf("unsupported upstream type: %s", f.config.Type)
	}
}

func (f *Forwarder) exchangeRaw(ctx context.Context, query []byte) ([]byte, error) {
	network := string(f.config.Type)
	addr := f.config.Address

	dialer := net.Dialer{Timeout: f.config.Timeout}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", network, addr, err)
	}
	defer conn.Close()

	// Write query length prefix for TCP
	if f.config.Type == UpstreamTCP {
		length := make([]byte, 2)
		length[0] = byte(len(query) >> 8)
		length[1] = byte(len(query))
		if _, err := conn.Write(length); err != nil {
			return nil, err
		}
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	// Read response
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return buf[:n], nil
}

func (f *Forwarder) exchangeDoH(ctx context.Context, query []byte) ([]byte, error) {
	// Strip EDNS0 OPT record (ARCOUNT) — DoH doesn't need UDP payload negotiation
	clean := stripEDNS0(query)
	if clean == nil {
		clean = query
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://"+hostFromAddr(f.config.Address)+"/dns-query",
		bytes.NewReader(clean))
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("doh read: %w", err)
	}
	return body, nil
}

func (f *Forwarder) exchangeDoT(ctx context.Context, query []byte) ([]byte, error) {
	dialer := net.Dialer{Timeout: f.config.Timeout}
	conn, err := tls.DialWithDialer(&dialer, "tcp", f.config.Address, f.tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dot dial: %w", err)
	}
	defer conn.Close()

	length := make([]byte, 2)
	length[0] = byte(len(query) >> 8)
	length[1] = byte(len(query))
	if _, err := conn.Write(length); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("dot read: %w", err)
	}
	return buf[:n], nil
}

func hostFromAddr(addr string) string {
	// Try URL parse first (for DoH addresses like https://1.1.1.1/dns-query)
	if u, err := url.Parse(addr); err == nil && u.Host != "" {
		if h, _, e := net.SplitHostPort(u.Host); e == nil {
			return h
		}
		return u.Host
	}
	// Fallback to host:port format
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// stripEDNS0 removes the OPT record from a DNS query (sets ARCOUNT to 0).
// Returns nil if no OPT record or query is too short.
func stripEDNS0(msg []byte) []byte {
	if len(msg) < 12 {
		return nil
	}
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))
	nscount := int(binary.BigEndian.Uint16(msg[8:10]))
	arcount := int(binary.BigEndian.Uint16(msg[10:12]))
	if arcount == 0 {
		return nil // no OPT to strip
	}
	// Parse QDNAME to find end of question section
	pos := 12
	for pos < len(msg) {
		if msg[pos] == 0 {
			pos += 5 // skip null label + QTYPE + QCLASS
			break
		}
		pos += int(msg[pos]) + 1
	}
	if pos > len(msg) {
		return nil
	}
	// Skip answer and authority sections
	for i := 0; i < ancount+nscount && pos < len(msg); i++ {
		if msg[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for pos < len(msg) && msg[pos] != 0 {
				pos += int(msg[pos]) + 1
			}
			pos++ // null label
		}
		if pos+10 > len(msg) {
			return nil
		}
		rdlen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		pos += 10 + rdlen
	}
	// Truncate: exclude OPT record, set ARCOUNT=0
	result := make([]byte, pos)
	copy(result, msg[:pos])
	binary.BigEndian.PutUint16(result[10:12], 0) // ARCOUNT = 0
	// Clear AD and CD bits in flags — DoH endpoints may reject them
	// Also strip any non-standard flags, keep only RD
	flags := binary.BigEndian.Uint16(result[2:4])
	flags &= 0x0100 // keep only RD
	binary.BigEndian.PutUint16(result[2:4], flags)
	return result
}
