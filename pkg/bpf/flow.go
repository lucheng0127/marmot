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

// WriteTCP writes a TCP flow entry (4-tuple) to the eBPF map.
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
