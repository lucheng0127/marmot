package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
	"github.com/lucheng0127/marmot/pkg/rule"
)

// FlowWriter is implemented by the server to write DNS results to eBPF Flow Cache.
type FlowWriter interface {
	WriteDNSFlow(ip net.IP, port uint16, protocol uint8, action uint8)
}

// Engine handles DNS query processing, caching, upstream forwarding,
// and Flow Cache writeback for domain-based rules.
type Engine struct {
	cache       *Cache
	upstreams   []*Forwarder
	timeout     time.Duration
	ruleEngine  *rule.Engine
	flowWriter  FlowWriter
}

func NewEngine(upstreams []*UpstreamConfig, cache *Cache, ruleEngine *rule.Engine, flowWriter FlowWriter) *Engine {
	e := &Engine{
		cache:      cache,
		timeout:    5 * time.Second,
		ruleEngine: ruleEngine,
		flowWriter: flowWriter,
	}
	for _, cfg := range upstreams {
		e.upstreams = append(e.upstreams, NewForwarder(cfg))
	}
	return e
}

func (e *Engine) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	qname := extractQuestion(query)
	if qname == "" {
		return e.forward(ctx, query)
	}

	if cached := e.cache.Get(qname); cached != nil {
		log.Debug("DNS cache HIT", map[string]interface{}{"qname": qname})
		return cached, nil
	}

	resp, err := e.forward(ctx, query)
	if err != nil {
		return nil, err
	}

	ttl := extractMinTTL(resp)
	e.cache.Put(qname, resp, time.Duration(ttl)*time.Second)
	log.Debug("DNS cache MISS", map[string]interface{}{
		"qname": qname,
		"ttl":   ttl,
	})

	// Phase 6.2: DNS -> Flow Cache writeback for domain-based rules
	e.writebackFlowCache(qname, resp)

	return resp, nil
}

// writebackFlowCache resolves domain rules and writes decisions to eBPF Flow Cache.
// Runs in background goroutine to avoid blocking DNS response.
func (e *Engine) writebackFlowCache(qname string, resp []byte) {
	if e.ruleEngine == nil || e.flowWriter == nil {
		return
	}
	go func() {
		addr := rule.Addr{Domain: qname}
		result := e.ruleEngine.Match(addr)
		if result.Action == rule.ActionProxy {
			return
		}
		ips := extractARecords(resp)
		for _, ip := range ips {
			e.flowWriter.WriteDNSFlow(ip, 0, 6, uint8(result.Action))
			e.flowWriter.WriteDNSFlow(ip, 0, 17, uint8(result.Action))
		}
	}()
}

// extractARecords extracts IPv4 addresses from a DNS response.
func extractARecords(msg []byte) []net.IP {
	var ips []net.IP
	if len(msg) < 12 || (msg[2]>>3)&0xF != 1 {
		return ips
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	if qdcount == 0 || ancount == 0 {
		return ips
	}

	pos := 12
	for i := 0; i < int(qdcount) && pos < len(msg); i++ {
		for pos < len(msg) && msg[pos] != 0 {
			pos += int(msg[pos]) + 1
		}
		pos += 5
	}

	for i := 0; i < int(ancount) && pos+12 <= len(msg); i++ {
		// Skip name (pointer or sequence)
		if msg[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for pos < len(msg) && msg[pos] != 0 {
				pos += int(msg[pos]) + 1
			}
			pos++
		}
		if pos+10 > len(msg) {
			break
		}
		rtype := binary.BigEndian.Uint16(msg[pos : pos+2])
		rdlen := binary.BigEndian.Uint16(msg[pos+8 : pos+10])
		pos += 10
		if rtype == 1 && rdlen == 4 && pos+4 <= len(msg) { // A record
			ips = append(ips, net.IPv4(msg[pos], msg[pos+1], msg[pos+2], msg[pos+3]))
		}
		pos += int(rdlen)
	}
	return ips
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

func extractQuestion(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	var buf bytes.Buffer
	pos := 12
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

func extractMinTTL(msg []byte) uint32 {
	if len(msg) < 12 || (msg[2]>>3)&0xF != 1 {
		return 300
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	if qdcount == 0 || ancount == 0 {
		return 300
	}
	pos := 12
	for i := 0; i < int(qdcount) && pos < len(msg); i++ {
		for pos < len(msg) && msg[pos] != 0 {
			pos += int(msg[pos]) + 1
		}
		pos += 5
	}
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
