package conntrack

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/lucheng0127/marmot/pkg/bpf"
	"github.com/lucheng0127/marmot/pkg/tproxy"
)

// SyncManager synchronizes Conntrack Cache decisions to the BPF Flow Map.
// This is the bridge between the user-space Slow Path and kernel-space Fast Path.
type SyncManager struct {
	flowMap *ebpf.Map
	cache   *Cache
}

// NewSyncManager creates a SyncManager backed by the given BPF map and Cache.
func NewSyncManager(flowMap *ebpf.Map, cache *Cache) *SyncManager {
	return &SyncManager{
		flowMap: flowMap,
		cache:   cache,
	}
}

// Writeback writes a flow decision from Conntrack Cache to the BPF Flow Map.
// This makes the decision available to the eBPF TC program for Fast Path.
func (s *SyncManager) Writeback(key FlowKey, d tproxy.Decision) error {
	if s.flowMap == nil {
		return fmt.Errorf("flow map not initialized")
	}

	// Convert conntrack.FlowKey to BPF flow_key
	var bpfKey bpf.MarmotFlowKey
	bpfKey.SrcIp = key.SrcIP
	bpfKey.DstIp = key.DstIP
	bpfKey.SrcPort = key.SrcPort
	bpfKey.DstPort = key.DstPort
	bpfKey.Protocol = key.Protocol

	// Build BPF flow_value
	var bpfVal bpf.MarmotFlowValue
	switch d {
	case tproxy.DecisionDirect:
		bpfVal.Action = 0 // FLOW_ACTION_DIRECT
	case tproxy.DecisionProxy:
		bpfVal.Action = 1 // FLOW_ACTION_PROXY
	default:
		return fmt.Errorf("unknown decision: %v", d)
	}

	// Set expiry (TTL from cache config, converted to seconds)
	ttlSeconds := uint32(s.cache.ttl.Seconds())
	if ttlSeconds <= 0 {
		ttlSeconds = 3600 // default 1h
	}
	bpfVal.ExpireAt = uint32(time.Now().Unix()) + ttlSeconds

	// Write to BPF map
	if err := s.flowMap.Put(&bpfKey, &bpfVal); err != nil {
		return fmt.Errorf("bpf map put: %w", err)
	}

	return nil
}

// Delete removes a flow entry from the BPF map.
func (s *SyncManager) Delete(key FlowKey) error {
	if s.flowMap == nil {
		return nil
	}

	var bpfKey bpf.MarmotFlowKey
	bpfKey.SrcIp = key.SrcIP
	bpfKey.DstIp = key.DstIP
	bpfKey.SrcPort = key.SrcPort
	bpfKey.DstPort = key.DstPort
	bpfKey.Protocol = key.Protocol

	if err := s.flowMap.Delete(&bpfKey); err != nil {
		return fmt.Errorf("bpf map delete: %w", err)
	}
	return nil
}

// FlushCache clears all entries from the BPF Flow Map.
// Used during rule reload or graceful shutdown.
func (s *SyncManager) FlushCache() error {
	if s.flowMap == nil {
		return nil
	}

	var prevKey bpf.MarmotFlowKey
	first := true
	for {
		var key bpf.MarmotFlowKey
		var err error
		if first {
			err = s.flowMap.NextKey(nil, &key)
			first = false
		} else {
			err = s.flowMap.NextKey(&prevKey, &key)
		}
		if err != nil {
			break
		}
		_ = s.flowMap.Delete(&key)
		prevKey = key
	}
	return nil
}

// Connect wires the Conntrack Cache's BPFWriter to this SyncManager.
// After calling Connect, every Cache.Insert will also write to the BPF map.
func (s *SyncManager) Connect() {
	s.cache.BPFWriter = func(key FlowKey, d tproxy.Decision) error {
		return s.Writeback(key, d)
	}
}

// Disconnect removes the BPF writeback callback.
func (s *SyncManager) Disconnect() {
	s.cache.BPFWriter = nil
}
