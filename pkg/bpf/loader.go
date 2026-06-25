package bpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Manager manages eBPF programs and maps.
type Manager struct {
	objs    MarmotObjects
	tcLink  link.Link
	iface   string
	pinPath string
	Stats   *StatsCollector
}

type LoadResult struct {
	TcpFlowMap    *ebpf.Map
	UdpFlowMap    *ebpf.Map
	CidrWhitelist *ebpf.Map
	StatsMap      *ebpf.Map
	Program       *ebpf.Program
}

func NewManager(iface string) *Manager {
	return &Manager{iface: iface}
}

func (m *Manager) Load() (*LoadResult, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	m.objs = MarmotObjects{}
	if err := LoadMarmotObjects(&m.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf: %w", err)
	}
	m.Stats = NewStatsCollector(m.objs.StatsMap)

	iface, err := net.InterfaceByName(m.iface)
	if err != nil {
		m.objs.Close()
		return nil, fmt.Errorf("interface %s: %w", m.iface, err)
	}

	tcxLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   m.objs.TcIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err == nil {
		m.tcLink = tcxLink
		goto done
	}

	m.pinPath = fmt.Sprintf("/sys/fs/bpf/marmot-%s-ingress", m.iface)
	_ = execCmd("rm", "-f", m.pinPath)
	if err := m.objs.TcIngress.Pin(m.pinPath); err != nil {
		m.objs.Close()
		return nil, fmt.Errorf("pin: %w", err)
	}
	_ = execCmd("tc", "qdisc", "del", "dev", m.iface, "clsact")
	_ = execCmd("tc", "qdisc", "add", "dev", m.iface, "clsact")
	if err := execCmd("tc", "filter", "add", "dev", m.iface, "ingress",
		"bpf", "da", "pinned", m.pinPath); err != nil {
		_ = m.objs.TcIngress.Unpin()
		m.objs.Close()
		return nil, fmt.Errorf("tc filter: %w", err)
	}

done:
	return &LoadResult{
		TcpFlowMap:    m.objs.TcpFlowMap,
		UdpFlowMap:    m.objs.UdpFlowMap,
		CidrWhitelist: m.objs.CidrWhitelist,
		StatsMap:      m.objs.StatsMap,
		Program:       m.objs.TcIngress,
	}, nil
}

func (m *Manager) Unload() error {
	if m.tcLink != nil {
		m.tcLink.Close()
	}
	if m.pinPath != "" {
		_ = execCmd("rm", "-f", m.pinPath)
		_ = execCmd("tc", "qdisc", "del", "dev", m.iface, "clsact")
	}
	m.objs.Close()
	return nil
}

func (m *Manager) AddCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	ones, _ := ipNet.Mask.Size()
	ip := ipNet.IP.To4()
	if ip == nil {
		return fmt.Errorf("not IPv4 CIDR: %s", cidr)
	}
	key := MarmotCidrKey{
		Prefixlen: uint32(ones),
		Prefix:    [4]uint8{ip[0], ip[1], ip[2], ip[3]},
	}
	var val uint8
	return m.objs.CidrWhitelist.Put(&key, &val)
}

func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0]) | (uint32(ip[1]) << 8) |
		(uint32(ip[2]) << 16) | (uint32(ip[3]) << 24)
}
