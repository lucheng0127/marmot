package conntrack

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/lucheng0127/marmot/pkg/bpf"
	"github.com/lucheng0127/marmot/pkg/tproxy"
)

// SyncManager synchronizes Conntrack Cache decisions to the BPF Flow Maps.
// Hybrid key design — TCP: 4-tuple (降维), UDP: 5-tuple.
type SyncManager struct {
	tcpFlowMap *ebpf.Map
	udpFlowMap *ebpf.Map
	cache      *Cache
}

// NewSyncManager creates a SyncManager.
func NewSyncManager(tcpFlowMap, udpFlowMap *ebpf.Map, cache *Cache) *SyncManager {
	return &SyncManager{
		tcpFlowMap: tcpFlowMap,
		udpFlowMap: udpFlowMap,
		cache:      cache,
	}
}

// Writeback writes a flow decision to the correct BPF map based on protocol.
func (s *SyncManager) Writeback(key FlowKey, d tproxy.Decision) error {
	ttlSeconds := uint32(s.cache.ttl.Seconds())
	if ttlSeconds <= 0 {
		ttlSeconds = 3600
	}
	expireAt := uint32(time.Now().Unix()) + ttlSeconds

	action := uint8(0) // direct
	if d == tproxy.DecisionProxy {
		action = 1
	}

	switch key.Protocol {
	case 6: // TCP — write to tcp_flow_map with 4-tuple key
		if s.tcpFlowMap == nil {
			return fmt.Errorf("tcp flow map not initialized")
		}
		var k bpf.MarmotTcpFlowKey
		k.SrcIp = key.SrcIP
		k.DstIp = key.DstIP
		k.DstPort = key.DstPort
		k.Protocol = 6
		var v bpf.MarmotFlowValue
		v.Action = action
		v.ExpireAt = expireAt
		return s.tcpFlowMap.Put(&k, &v)

	case 17: // UDP — write to udp_flow_map with 5-tuple key
		if s.udpFlowMap == nil {
			return fmt.Errorf("udp flow map not initialized")
		}
		var k bpf.MarmotUdpFlowKey
		k.SrcIp = key.SrcIP
		k.DstIp = key.DstIP
		k.SrcPort = key.SrcPort
		k.DstPort = key.DstPort
		k.Protocol = 17
		var v bpf.MarmotFlowValue
		v.Action = action
		v.ExpireAt = expireAt
		return s.udpFlowMap.Put(&k, &v)

	default:
		return fmt.Errorf("unsupported protocol: %d", key.Protocol)
	}
}

// Delete removes a flow entry from the correct BPF map.
func (s *SyncManager) Delete(key FlowKey) error {
	switch key.Protocol {
	case 6:
		if s.tcpFlowMap == nil {
			return nil
		}
		var k bpf.MarmotTcpFlowKey
		k.SrcIp = key.SrcIP
		k.DstIp = key.DstIP
		k.DstPort = key.DstPort
		k.Protocol = 6
		return s.tcpFlowMap.Delete(&k)
	case 17:
		if s.udpFlowMap == nil {
			return nil
		}
		var k bpf.MarmotUdpFlowKey
		k.SrcIp = key.SrcIP
		k.DstIp = key.DstIP
		k.SrcPort = key.SrcPort
		k.DstPort = key.DstPort
		k.Protocol = 17
		return s.udpFlowMap.Delete(&k)
	}
	return nil
}

// FlushCache clears all entries from both BPF Flow Maps.
func (s *SyncManager) FlushCache() error {
	if s.tcpFlowMap != nil {
		if err := flushMap(s.tcpFlowMap); err != nil {
			return err
		}
	}
	if s.udpFlowMap != nil {
		if err := flushMap(s.udpFlowMap); err != nil {
			return err
		}
	}
	return nil
}

func flushMap(m *ebpf.Map) error {
	var prev interface{}
	first := true
	for {
		var key interface{}
		var err error
		if first {
			err = m.NextKey(nil, &key)
			first = false
		} else {
			err = m.NextKey(&prev, &key)
		}
		if err != nil {
			break
		}
		_ = m.Delete(key)
		prev = key
	}
	return nil
}

// Connect wires the Conntrack Cache's BPFWriter to this SyncManager.
func (s *SyncManager) Connect() {
	s.cache.BPFWriter = func(key FlowKey, d tproxy.Decision) error {
		return s.Writeback(key, d)
	}
}

// Disconnect removes the BPF writeback callback.
func (s *SyncManager) Disconnect() {
	s.cache.BPFWriter = nil
}
