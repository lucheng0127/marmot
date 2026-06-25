package bpf

import (
	"net"
	"time"

	"github.com/cilium/ebpf"
)

// FlowEntry represents a cached flow decision stored in the BPF map.
type FlowEntry struct {
	Action  uint8
	TTL     uint32 // expiration timestamp (unix seconds)
}

// FlowWriter writes flow decisions to the BPF Flow Cache maps.
type FlowWriter struct {
	tcpFlowMap *ebpf.Map
	udpFlowMap *ebpf.Map
}

func NewFlowWriter(tcpMap, udpMap *ebpf.Map) *FlowWriter {
	return &FlowWriter{tcpFlowMap: tcpMap, udpFlowMap: udpMap}
}

// WriteDNSFlow writes a DNS-resolved IP decision to the Flow Cache.
// src_ip is set to 0 — only matches when eBPF key allows wildcard.
// Currently limited by 4-tuple key requiring src_ip.
func (w *FlowWriter) WriteDNSFlow(ip net.IP, port uint16, protocol uint8, action uint8) {
	if protocol == 6 {
		var k MarmotTcpFlowKey
		k.DstIp = ipToLE(ip)
		k.DstPort = htons(port)
		k.Protocol = 6
		var v MarmotFlowValue
		v.Action = action
		v.ExpireAt = uint32(time.Now().Unix()) + 3600
		_ = w.tcpFlowMap.Put(&k, &v)
	} else {
		var k MarmotUdpFlowKey
		k.DstIp = ipToLE(ip)
		k.DstPort = htons(port)
		k.Protocol = 17
		var v MarmotFlowValue
		v.Action = action
		v.ExpireAt = uint32(time.Now().Unix()) + 300
		_ = w.udpFlowMap.Put(&k, &v)
	}
}
func (w *FlowWriter) WriteTCP(srcIP, dstIP net.IP, dstPort uint16, action uint8, ttl uint32) error {
	var k MarmotTcpFlowKey
	k.SrcIp = ipToLE(srcIP)
	k.DstIp = ipToLE(dstIP)
	k.DstPort = htons(dstPort)
	k.Protocol = 6

	var v MarmotFlowValue
	v.Action = action
	v.ExpireAt = uint32(time.Now().Unix()) + ttl

	return w.tcpFlowMap.Put(&k, &v)
}

// WriteUDP writes a UDP flow entry (5-tuple) to the eBPF map.
func (w *FlowWriter) WriteUDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, action uint8, ttl uint32) error {
	var k MarmotUdpFlowKey
	k.SrcIp = ipToLE(srcIP)
	k.SrcPort = htons(srcPort)
	k.DstIp = ipToLE(dstIP)
	k.DstPort = htons(dstPort)
	k.Protocol = 17

	var v MarmotFlowValue
	v.Action = action
	v.ExpireAt = uint32(time.Now().Unix()) + ttl

	return w.udpFlowMap.Put(&k, &v)
}

// DeleteTCP deletes a TCP flow entry.
func (w *FlowWriter) DeleteTCP(srcIP, dstIP net.IP, dstPort uint16) error {
	var k MarmotTcpFlowKey
	k.SrcIp = ipToLE(srcIP)
	k.DstIp = ipToLE(dstIP)
	k.DstPort = htons(dstPort)
	k.Protocol = 6

	return w.tcpFlowMap.Delete(&k)
}

// DeleteUDP deletes a UDP flow entry.
func (w *FlowWriter) DeleteUDP(srcIP, dstIP net.IP, srcPort, dstPort uint16) error {
	var k MarmotUdpFlowKey
	k.SrcIp = ipToLE(srcIP)
	k.SrcPort = htons(srcPort)
	k.DstIp = ipToLE(dstIP)
	k.DstPort = htons(dstPort)
	k.Protocol = 17

	return w.udpFlowMap.Delete(&k)
}

func ipToLE(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0]) | (uint32(ip[1]) << 8) |
		(uint32(ip[2]) << 16) | (uint32(ip[3]) << 24)
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func init() { _ = time.Second }
