package dns

import (
	"context"
	"crypto/tls"
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
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
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
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Scheme: "https", Host: hostFromAddr(f.config.Address), Path: "/dns-query"},
		Header: http.Header{
			"Content-Type": {"application/dns-message"},
			"Accept":       {"application/dns-message"},
		},
		Body: io.NopCloser(byteReader{query}),
	}
	resp, err := f.client.Do(req.WithContext(ctx))
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
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

type byteReader struct{ data []byte }

func (r byteReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
