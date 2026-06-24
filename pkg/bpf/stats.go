package bpf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// Stats counter indices — must match marmot_bpf.h on the C side.
const (
	StatsTotalPackets = 0
	StatsCIDRHit      = 1
	StatsFlowHit      = 2
	StatsFlowMiss     = 3
	StatsProxyMark    = 4
	StatsBlockDrop    = 5
)

var statNames = map[uint32]string{
	StatsTotalPackets: "total_packets",
	StatsCIDRHit:      "cidr_hit",
	StatsFlowHit:      "flow_hit",
	StatsFlowMiss:     "flow_miss",
	StatsProxyMark:    "proxy_mark",
	StatsBlockDrop:    "block_drop",
}

// StatsCollector reads and resets eBPF statistics counters.
type StatsCollector struct {
	statsMap *ebpf.Map
}

// NewStatsCollector creates a collector backed by the given BPF stats map.
func NewStatsCollector(statsMap *ebpf.Map) *StatsCollector {
	return &StatsCollector{statsMap: statsMap}
}

// Snapshot contains a point-in-time read of all counters.
type Snapshot struct {
	TotalPackets uint64
	CIDRHit      uint64
	FlowHit      uint64
	FlowMiss     uint64
	ProxyMark    uint64
	BlockDrop    uint64
}

// Read returns a snapshot of all current counter values.
func (s *StatsCollector) Read() (*Snapshot, error) {
	snap := &Snapshot{}

	if err := s.statsMap.Lookup(uint32(StatsTotalPackets), &snap.TotalPackets); err != nil {
		return nil, fmt.Errorf("read total_packets: %w", err)
	}
	if err := s.statsMap.Lookup(uint32(StatsCIDRHit), &snap.CIDRHit); err != nil {
		return nil, fmt.Errorf("read cidr_hit: %w", err)
	}
	if err := s.statsMap.Lookup(uint32(StatsFlowHit), &snap.FlowHit); err != nil {
		return nil, fmt.Errorf("read flow_hit: %w", err)
	}
	if err := s.statsMap.Lookup(uint32(StatsFlowMiss), &snap.FlowMiss); err != nil {
		return nil, fmt.Errorf("read flow_miss: %w", err)
	}
	if err := s.statsMap.Lookup(uint32(StatsProxyMark), &snap.ProxyMark); err != nil {
		return nil, fmt.Errorf("read proxy_mark: %w", err)
	}
	if err := s.statsMap.Lookup(uint32(StatsBlockDrop), &snap.BlockDrop); err != nil {
		return nil, fmt.Errorf("read block_drop: %w", err)
	}

	return snap, nil
}

// String returns a human-readable representation of the stats snapshot.
func (s *Snapshot) String() string {
	var b strings.Builder
	b.WriteString("eBPF Stats:\n")
	b.WriteString(fmt.Sprintf("  total_packets: %d\n", s.TotalPackets))
	b.WriteString(fmt.Sprintf("  cidr_hit:      %d\n", s.CIDRHit))
	b.WriteString(fmt.Sprintf("  flow_hit:      %d\n", s.FlowHit))
	b.WriteString(fmt.Sprintf("  flow_miss:     %d\n", s.FlowMiss))
	b.WriteString(fmt.Sprintf("  proxy_mark:    %d\n", s.ProxyMark))
	b.WriteString(fmt.Sprintf("  block_drop:    %d\n", s.BlockDrop))
	return b.String()
}

// Reset resets all counters to zero in the BPF map.
func (s *StatsCollector) Reset() error {
	for idx := uint32(0); idx < 16; idx++ {
		zero := uint64(0)
		if err := s.statsMap.Put(idx, zero); err != nil {
			return fmt.Errorf("reset counter %d: %w", idx, err)
		}
	}
	return nil
}
