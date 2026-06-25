package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
)

// Engine handles DNS query processing, caching, and upstream forwarding.
type Engine struct {
	cache     *Cache
	upstreams []*Forwarder
	timeout   time.Duration
}

func NewEngine(upstreams []*UpstreamConfig, cache *Cache) *Engine {
	e := &Engine{
		cache:   cache,
		timeout: 5 * time.Second,
	}
	for _, cfg := range upstreams {
		e.upstreams = append(e.upstreams, NewForwarder(cfg))
	}
	return e
}

// Resolve performs DNS resolution, checking cache first.
func (e *Engine) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	// Extract question name for cache key
	qname := extractQuestion(query)
	if qname == "" {
		// Can't extract question — forward directly
		return e.forward(ctx, query)
	}

	// Check cache
	if cached := e.cache.Get(qname); cached != nil {
		log.Debug("DNS cache HIT", map[string]interface{}{"qname": qname})
		return cached, nil
	}

	// Forward to upstream
	resp, err := e.forward(ctx, query)
	if err != nil {
		return nil, err
	}

	// Cache the response (extract TTL from answer)
	ttl := extractMinTTL(resp)
	e.cache.Put(qname, resp, time.Duration(ttl)*time.Second)
	log.Debug("DNS cache MISS", map[string]interface{}{
		"qname": qname,
		"ttl":   ttl,
	})

	return resp, nil
}

func (e *Engine) forward(ctx context.Context, query []byte) ([]byte, error) {
	var lastErr error
	for _, f := range e.upstreams {
		resp, err := f.Exchange(ctx, query)
		if err != nil {
			lastErr = err
			log.Warn("upstream failed", map[string]interface{}{
				"addr": f.config.Address,
				"err":  err.Error(),
			})
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}

// extractQuestion extracts the QNAME from a DNS query.
func extractQuestion(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	var buf bytes.Buffer
	pos := 12 // skip header
	for pos < len(msg) {
		length := int(msg[pos])
		if length == 0 {
			break
		}
		if pos+1+length > len(msg) {
			return ""
		}
		if buf.Len() > 0 {
			buf.WriteByte('.')
		}
		buf.Write(msg[pos+1 : pos+1+length])
		pos += 1 + length
	}
	return buf.String()
}

// extractMinTTL returns the minimum TTL from a DNS response.
func extractMinTTL(msg []byte) uint32 {
	if len(msg) < 12 || (msg[2]>>3)&0xF != 1 {
		return 300 // default if not a response or can't parse
	}
	// Parse header
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	if qdcount == 0 || ancount == 0 {
		return 300
	}

	// Skip question section
	pos := 12
	for i := 0; i < int(qdcount) && pos < len(msg); i++ {
		for pos < len(msg) && msg[pos] != 0 {
			pos += int(msg[pos]) + 1
		}
		pos += 5 // null label + QTYPE + QCLASS
	}

	// Read first answer's TTL
	if pos+10 > len(msg) {
		return 300
	}
	ttl := binary.BigEndian.Uint32(msg[pos+6 : pos+10])
	if ttl < 1 {
		ttl = 1
	}
	if ttl > 86400 {
		ttl = 86400
	}
	return ttl
}
