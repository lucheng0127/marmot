package bpf

import (
	"net"

	"github.com/cilium/ebpf"
)

// FlowKey is the user-space representation of a 5-tuple flow key.
type FlowKey struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8 // 6=TCP, 17=UDP
}

// FlowValue is the user-space representation of a cached flow decision.
type FlowValue struct {
	Action      uint8  // 0=direct, 1=proxy, 2=block
	OutboundTag string // outbound group tag (up to 15 chars)
	ExpireAt    uint32 // unix timestamp
	HitCount    uint32
}

// FlowMapOps provides operations on the flow BPF map.
type FlowMapOps struct {
	bpfMap *ebpf.Map
}

// NewFlowMapOps creates a FlowMapOps backed by the given BPF map.
func NewFlowMapOps(bpfMap *ebpf.Map) *FlowMapOps {
	return &FlowMapOps{bpfMap: bpfMap}
}

// Put writes a flow entry into the BPF map.
func (f *FlowMapOps) Put(key FlowKey, value FlowValue) error {
	var k MarmotFlowKey
	var v MarmotFlowValue

	// Fill key
	k.SrcIp = IPToUint32(key.SrcIP)
	k.DstIp = IPToUint32(key.DstIP)
	k.SrcPort = htons(key.SrcPort)
	k.DstPort = htons(key.DstPort)
	k.Protocol = key.Protocol

	// Fill value
	v.Action = value.Action
	v.ExpireAt = value.ExpireAt
	v.HitCount = value.HitCount

	// Copy outbound tag (max 15 chars + null)
	tagLen := len(value.OutboundTag)
	if tagLen > 15 {
		tagLen = 15
	}
	for i := 0; i < tagLen; i++ {
		v.OutboundTag[i] = value.OutboundTag[i]
	}
	v.OutboundTag[tagLen] = 0 // null terminator

	return f.bpfMap.Put(&k, &v)
}

// Get looks up a flow entry in the BPF map.
func (f *FlowMapOps) Get(key FlowKey) (*FlowValue, error) {
	var k MarmotFlowKey
	k.SrcIp = IPToUint32(key.SrcIP)
	k.DstIp = IPToUint32(key.DstIP)
	k.SrcPort = htons(key.SrcPort)
	k.DstPort = htons(key.DstPort)
	k.Protocol = key.Protocol

	var v MarmotFlowValue
	if err := f.bpfMap.Lookup(&k, &v); err != nil {
		return nil, err
	}

	// Extract outbound tag (null-terminated string)
	var tagBytes []byte
	for _, b := range v.OutboundTag {
		if b == 0 {
			break
		}
		tagBytes = append(tagBytes, b)
	}

	return &FlowValue{
		Action:      v.Action,
		OutboundTag: string(tagBytes),
		ExpireAt:    v.ExpireAt,
		HitCount:    v.HitCount,
	}, nil
}

// Delete removes a flow entry from the BPF map.
func (f *FlowMapOps) Delete(key FlowKey) error {
	var k MarmotFlowKey
	k.SrcIp = IPToUint32(key.SrcIP)
	k.DstIp = IPToUint32(key.DstIP)
	k.SrcPort = htons(key.SrcPort)
	k.DstPort = htons(key.DstPort)
	k.Protocol = key.Protocol

	return f.bpfMap.Delete(&k)
}

// Iterate iterates over all entries in the flow map.
// The callback receives each key-value pair. Return false to stop iteration.
func (f *FlowMapOps) Iterate(cb func(FlowKey, FlowValue) bool) error {
	var prevKey MarmotFlowKey
	first := true

	for {
		var key MarmotFlowKey
		var value MarmotFlowValue

		var err error
		if first {
			err = f.bpfMap.NextKey(nil, &key)
			first = false
		} else {
			err = f.bpfMap.NextKey(&prevKey, &key)
		}

		if err != nil {
			break // no more entries
		}

		if err := f.bpfMap.Lookup(&key, &value); err != nil {
			break
		}

		// Convert to user-space types
		fk := FlowKey{
			SrcIP:    uint32ToIP(key.SrcIp),
			DstIP:    uint32ToIP(key.DstIp),
			SrcPort:  ntohs(key.SrcPort),
			DstPort:  ntohs(key.DstPort),
			Protocol: key.Protocol,
		}

		var tagBytes []byte
		for _, b := range value.OutboundTag {
			if b == 0 {
				break
			}
			tagBytes = append(tagBytes, b)
		}

		fv := FlowValue{
			Action:      value.Action,
			OutboundTag: string(tagBytes),
			ExpireAt:    value.ExpireAt,
			HitCount:    value.HitCount,
		}

		if !cb(fk, fv) {
			break
		}

		prevKey = key
	}

	return nil
}

// Count returns the number of entries in the flow map.
func (f *FlowMapOps) Count() (int, error) {
	count := 0
	err := f.Iterate(func(FlowKey, FlowValue) bool {
		count++
		return true
	})
	return count, err
}

// --- helpers ---

// htons converts from host to network byte order (big-endian).
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// ntohs converts from network byte order to host order.
func ntohs(v uint16) uint16 {
	return htons(v) // same operation (swap bytes)
}

// uint32ToIP converts a uint32 network-order IP to net.IP.
func uint32ToIP(v uint32) net.IP {
	return net.IPv4(
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}
