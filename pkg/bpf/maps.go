package bpf

import (
	"net"

	"github.com/cilium/ebpf"
)

// -- byte order helpers --

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// FlowValue is the user-space representation of a cached flow decision.
type FlowValue struct {
	Action      uint8  // 0=direct, 1=proxy, 2=block
	OutboundTag string // outbound group tag (up to 15 chars)
	ExpireAt    uint32 // unix timestamp
	HitCount    uint32
}

// TCPFlowKey is the 4-tuple key for TCP flow cache (降维, no src_port).
type TCPFlowKey struct {
	SrcIP   net.IP
	DstIP   net.IP
	DstPort uint16
}

// UDPFlowKey is the 5-tuple key for UDP flow cache.
type UDPFlowKey struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
}

// TCPFlowMapOps provides operations on the TCP flow BPF map.
type TCPFlowMapOps struct {
	bpfMap *ebpf.Map
}

// NewTCPFlowMapOps creates a TCPFlowMapOps.
func NewTCPFlowMapOps(bpfMap *ebpf.Map) *TCPFlowMapOps {
	return &TCPFlowMapOps{bpfMap: bpfMap}
}

// Put writes a TCP flow entry into the BPF map.
func (f *TCPFlowMapOps) Put(key TCPFlowKey, value FlowValue) error {
	var k MarmotTcpFlowKey
	var v MarmotFlowValue
	k.SrcIp = IPToUint32(key.SrcIP)
	k.DstIp = IPToUint32(key.DstIP)
	k.DstPort = htons(key.DstPort)
	k.Protocol = 6
	v.Action = value.Action
	v.ExpireAt = value.ExpireAt
	v.HitCount = value.HitCount
	return f.bpfMap.Put(&k, &v)
}

// Get looks up a TCP flow entry.
func (f *TCPFlowMapOps) Get(key TCPFlowKey) (*FlowValue, error) {
	var k MarmotTcpFlowKey
	k.SrcIp = IPToUint32(key.SrcIP)
	k.DstIp = IPToUint32(key.DstIP)
	k.DstPort = htons(key.DstPort)
	k.Protocol = 6
	var v MarmotFlowValue
	if err := f.bpfMap.Lookup(&k, &v); err != nil {
		return nil, err
	}
	return &FlowValue{Action: v.Action, ExpireAt: v.ExpireAt, HitCount: v.HitCount}, nil
}

// Delete removes a TCP flow entry.
func (f *TCPFlowMapOps) Delete(key TCPFlowKey) error {
	var k MarmotTcpFlowKey
	k.SrcIp = IPToUint32(key.SrcIP)
	k.DstIp = IPToUint32(key.DstIP)
	k.DstPort = htons(key.DstPort)
	k.Protocol = 6
	return f.bpfMap.Delete(&k)
}

// Count returns the number of entries in the TCP flow map.
func (f *TCPFlowMapOps) Count() (int, error) {
	count := 0
	var prev MarmotTcpFlowKey
	first := true
	for {
		var key MarmotTcpFlowKey
		var err error
		if first {
			err = f.bpfMap.NextKey(nil, &key)
			first = false
		} else {
			err = f.bpfMap.NextKey(&prev, &key)
		}
		if err != nil {
			break
		}
		count++
		prev = key
	}
	return count, nil
}

// UDPFlowMapOps provides operations on the UDP flow BPF map.
type UDPFlowMapOps struct {
	bpfMap *ebpf.Map
}

// NewUDPFlowMapOps creates a UDPFlowMapOps.
func NewUDPFlowMapOps(bpfMap *ebpf.Map) *UDPFlowMapOps {
	return &UDPFlowMapOps{bpfMap: bpfMap}
}

// Put writes a UDP flow entry into the BPF map.
func (f *UDPFlowMapOps) Put(key UDPFlowKey, value FlowValue) error {
	var k MarmotUdpFlowKey
	var v MarmotFlowValue
	k.SrcIp = IPToUint32(key.SrcIP)
	k.DstIp = IPToUint32(key.DstIP)
	k.SrcPort = htons(key.SrcPort)
	k.DstPort = htons(key.DstPort)
	k.Protocol = 17
	v.Action = value.Action
	v.ExpireAt = value.ExpireAt
	v.HitCount = value.HitCount
	return f.bpfMap.Put(&k, &v)
}

// Delete removes a UDP flow entry.
func (f *UDPFlowMapOps) Delete(key UDPFlowKey) error {
	var k MarmotUdpFlowKey
	k.SrcIp = IPToUint32(key.SrcIP)
	k.DstIp = IPToUint32(key.DstIP)
	k.SrcPort = htons(key.SrcPort)
	k.DstPort = htons(key.DstPort)
	k.Protocol = 17
	return f.bpfMap.Delete(&k)
}

// Count returns the number of entries in the UDP flow map.
func (f *UDPFlowMapOps) Count() (int, error) {
	count := 0
	var prev MarmotUdpFlowKey
	first := true
	for {
		var key MarmotUdpFlowKey
		var err error
		if first {
			err = f.bpfMap.NextKey(nil, &key)
			first = false
		} else {
			err = f.bpfMap.NextKey(&prev, &key)
		}
		if err != nil {
			break
		}
		count++
		prev = key
	}
	return count, nil
}
