package dns

import (
	"sync"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
)

// UpstreamManager manages a set of DNS upstream configurations.
type UpstreamManager struct {
	mu        sync.RWMutex
	upstreams []*UpstreamConfig
	engine    *Engine
}

func NewUpstreamManager(upstreams []*UpstreamConfig, engine *Engine) *UpstreamManager {
	return &UpstreamManager{
		upstreams: upstreams,
		engine:    engine,
	}
}

// Reload replaces the upstream configuration and rebuilds forwarders.
func (m *UpstreamManager) Reload(upstreams []*UpstreamConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreams = upstreams

	// Rebuild engine's forwarders
	var forwarders []*Forwarder
	for _, cfg := range upstreams {
		forwarders = append(forwarders, NewForwarder(cfg))
	}
	m.engine.upstreams = forwarders

	log.Info("DNS upstream reloaded", map[string]interface{}{
		"count": len(upstreams),
	})
}

// Upstreams returns the current upstream list.
func (m *UpstreamManager) Upstreams() []*UpstreamConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*UpstreamConfig, len(m.upstreams))
	copy(result, m.upstreams)
	return result
}

// DefaultUpstreams returns the default upstream configuration.
func DefaultUpstreams() []*UpstreamConfig {
	return []*UpstreamConfig{
		{
			Type:    UpstreamUDP,
			Address: "223.5.5.5:53",
			Timeout: 5 * time.Second,
			Tag:     "default",
		},
		{
			Type:    UpstreamDoH,
			Address: "https://dns.google/dns-query",
			Timeout: 5 * time.Second,
			Tag:     "doh-google",
		},
	}
}
