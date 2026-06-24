package bpf

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Manager manages the lifecycle of eBPF programs and maps.
type Manager struct {
	objs    MarmotObjects
	tcLink  link.Link
	iface   string
	pinPath string // BPFFS pin path for legacy TC
	Stats   *StatsCollector
}

// LoadResult contains references to loaded eBPF objects.
type LoadResult struct {
	TcpFlowMap    *ebpf.Map // TCP: 4-tuple key (降维)
	UdpFlowMap    *ebpf.Map // UDP: 5-tuple key
	CidrWhitelist *ebpf.Map
	StatsMap      *ebpf.Map
	Program       *ebpf.Program
}

// NewManager creates a new Manager but does not load any programs.
func NewManager(iface string) *Manager {
	return &Manager{iface: iface}
}

// Load loads and attaches the eBPF programs to the network interface.
// Uses TCX (kernel 6.6+) or falls back to legacy TC (kernel 5.10+).
func (m *Manager) Load() (*LoadResult, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	if err := LoadMarmotObjects(&m.objs, nil); err != nil {
		return nil, fmt.Errorf("load marmot objects: %w", err)
	}
	m.Stats = NewStatsCollector(m.objs.StatsMap)

	iface, err := net.InterfaceByName(m.iface)
	if err != nil {
		m.objs.Close()
		return nil, fmt.Errorf("lookup interface %s: %w", m.iface, err)
	}

	m.tcLink, err = m.attachTC(iface)
	if err != nil {
		m.objs.Close()
		return nil, fmt.Errorf("attach TC on %s: %w", m.iface, err)
	}

	return &LoadResult{
		TcpFlowMap:    m.objs.TcpFlowMap,
		UdpFlowMap:    m.objs.UdpFlowMap,
		CidrWhitelist: m.objs.CidrWhitelist,
		StatsMap:      m.objs.StatsMap,
		Program:       m.objs.TcIngress,
	}, nil
}

// attachTC tries TCX first, falls back to legacy clsact + tc filter.
func (m *Manager) attachTC(iface *net.Interface) (link.Link, error) {
	tcxLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   m.objs.TcIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err == nil {
		return tcxLink, nil
	}

	// TCX failed — use legacy TC (clsact + tc filter, kernel 5.10+)
	if err := m.setupLegacyTC(iface.Name); err != nil {
		return nil, fmt.Errorf("TCX unavailable (%v) and legacy TC failed: %w", err, err)
	}
	return nil, nil // legacy TC, cleanup is manual in Unload()
}

// setupLegacyTC creates clsact qdisc + attaches BPF program via tc CLI.
func (m *Manager) setupLegacyTC(iface string) error {
	// Also clean up old clsact qdisc to ensure clean state
	_ = execCmd("tc", "qdisc", "del", "dev", iface, "clsact")

	if err := execCmd("tc", "qdisc", "add", "dev", iface, "clsact"); err != nil {
		// clsact may already exist from a previous run
		// Try replacing instead
		if err2 := execCmd("tc", "qdisc", "replace", "dev", iface, "clsact"); err2 != nil {
			return fmt.Errorf("create clsact: %v (add: %w)", err, err)
		}
	}
	// Remove any existing pin file from a previous run
	pinPath := fmt.Sprintf("/sys/fs/bpf/marmot-%s-ingress", iface)
	_ = execCmd("rm", "-f", pinPath)

	// Remove any existing ingress filters on this interface
	_ = execCmd("tc", "filter", "del", "dev", iface, "ingress")

	if err := m.objs.TcIngress.Pin(pinPath); err != nil {
		return fmt.Errorf("pin program: %w", err)
	}
	m.pinPath = pinPath
	if err := execCmd("tc", "filter", "add", "dev", iface, "ingress",
		"bpf", "da", "pinned", pinPath); err != nil {
		// filter may already exist, try deleting first then adding again
		_ = execCmd("tc", "filter", "del", "dev", iface, "ingress",
			"bpf", "da", "pinned", pinPath)
		if err2 := execCmd("tc", "filter", "add", "dev", iface, "ingress",
			"bpf", "da", "pinned", pinPath); err2 != nil {
			_ = m.objs.TcIngress.Unpin()
			return fmt.Errorf("add tc filter: %v (first: %w)", err2, err)
		}
	}
	return nil
}

// Unload detaches the TC program and closes all eBPF objects.
func (m *Manager) Unload() error {
	var errs []error

	// Remove legacy TC if we used it
	if m.pinPath != "" {
		iface := m.iface
		if err := execCmd("tc", "qdisc", "del", "dev", iface, "clsact"); err != nil {
			errs = append(errs, fmt.Errorf("remove clsact: %w", err))
		}
		if err := m.objs.TcIngress.Unpin(); err != nil {
			errs = append(errs, fmt.Errorf("unpin: %w", err))
		}
	}

	// Close TCX link if we used it
	if m.tcLink != nil && m.pinPath == "" {
		if err := m.tcLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close TC link: %w", err))
		}
	}

	if err := m.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close objects: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("unload errors: %v", errs)
	}
	return nil
}

// AddCIDR adds a CIDR entry to the whitelist (LPM_TRIE map).
func (m *Manager) AddCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return fmt.Errorf("not an IPv4 CIDR: %s", cidr)
	}
	ones, _ := ipNet.Mask.Size()
	key := MarmotCidrKey{
		Prefixlen: uint32(ones),
		Prefix:    [4]uint8{ip[0], ip[1], ip[2], ip[3]},
	}
	var val MarmotCidrValue
	return m.objs.CidrWhitelist.Put(&key, &val)
}

// RemoveCIDR removes a CIDR entry from the whitelist.
func (m *Manager) RemoveCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	ones, _ := ipNet.Mask.Size()
	ip := ipNet.IP.To4()
	if ip == nil {
		return fmt.Errorf("not an IPv4 CIDR: %s", cidr)
	}
	key := MarmotCidrKey{
		Prefixlen: uint32(ones),
		Prefix:    [4]uint8{ip[0], ip[1], ip[2], ip[3]},
	}
	return m.objs.CidrWhitelist.Delete(&key)
}

// IPToUint32 converts IPv4 address bytes to LE uint32 (matching eBPF __u32 on ARM/x86).
// eBPF loads ip->saddr as native-endian __u32 from the packet's network-order bytes.
// On LE hardware (ARM/x86), byte C0 A8 64 02 becomes u32 0x0264A8C0.
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0]) | (uint32(ip[1]) << 8) |
		(uint32(ip[2]) << 16) | (uint32(ip[3]) << 24)
}

func execCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s (%w)", name, args, string(out), err)
	}
	return nil
}
