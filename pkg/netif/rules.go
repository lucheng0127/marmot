// Package netif automates iptables + iproute2 setup/cleanup.
// All operations are IDEMPOTENT: safe to call multiple times.
package netif

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/lucheng0127/marmot/pkg/log"
)

// Rules manages iptables + iproute2 rules for TProxy and DNS.
type Rules struct {
	lanSubnet string // CIDR from config, e.g. "192.168.100.0/24"
	setup     bool
}

// New creates a Rules manager. lanSubnet is the LAN subnet used for SNAT MASQUERADE rules.
func New(lanSubnet string) *Rules {
	if lanSubnet == "" {
		lanSubnet = "192.168.100.0/24"
	}
	return &Rules{lanSubnet: lanSubnet}
}

// Setup configures all required network rules. Idempotent.
// 1. Remove any existing rules first (clean slate)
// 2. Then add fresh rules
func (r *Rules) Setup() error {
	// Phase 1: Destroy any old chain/state
	_ = run("iptables", "-t", "mangle", "-D", "PREROUTING", "-m", "mark", "--mark", "1", "-j", "MARMOT_TPROXY")
	_ = run("iptables", "-t", "mangle", "-F", "MARMOT_TPROXY")
	_ = run("iptables", "-t", "mangle", "-X", "MARMOT_TPROXY")
	_ = run("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53")
	_ = run("ip", "rule", "del", "fwmark", "1", "lookup", "100", "priority", "1000")
	_ = run("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "100")

	// Phase 2: Create fresh rules
	cmds := [][]string{
		{"ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100"},
		{"ip", "rule", "add", "fwmark", "1", "lookup", "100", "priority", "1000"},
		{"iptables", "-t", "mangle", "-N", "MARMOT_TPROXY"},
		{"iptables", "-t", "mangle", "-A", "PREROUTING", "-m", "mark", "--mark", "1", "-j", "MARMOT_TPROXY"},
		{"iptables", "-t", "mangle", "-A", "MARMOT_TPROXY", "-p", "tcp", "-j", "TPROXY", "--on-port", "1080", "--on-ip", "127.0.0.1"},
		{"iptables", "-t", "mangle", "-A", "MARMOT_TPROXY", "-p", "udp", "-j", "TPROXY", "--on-port", "1080", "--on-ip", "127.0.0.1"},
		{"iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"},
		// DNS reply exception: avoid MASQUERADE rewriting src of local DNS responses
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", r.lanSubnet, "-p", "udp", "--sport", "53", "-j", "ACCEPT"},
		// SNAT for LAN traffic to internet
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", r.lanSubnet, "-j", "MASQUERADE"},
	}

	for _, args := range cmds {
		if err := run(args[0], args[1:]...); err != nil {
			log.Warn("net rule add failed", map[string]interface{}{
				"cmd":   strings.Join(args, " "),
				"error": err.Error(),
			})
		}
	}

	r.setup = true
	log.Info("network rules configured", map[string]interface{}{"lan_subnet": r.lanSubnet})
	return nil
}

// Cleanup removes all rules. Idempotent — loops until nothing left.
func (r *Rules) Cleanup() error {
	if !r.setup {
		return nil
	}

	// iptables rule deletion loops — handles duplicate rules
	for i := 0; i < 10; i++ {
		if err := run("iptables", "-t", "mangle", "-D", "PREROUTING", "-m", "mark", "--mark", "1", "-j", "MARMOT_TPROXY"); err != nil {
			break
		}
	}
	_ = run("iptables", "-t", "mangle", "-F", "MARMOT_TPROXY")
	_ = run("iptables", "-t", "mangle", "-X", "MARMOT_TPROXY")

	for i := 0; i < 10; i++ {
		if err := run("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"); err != nil {
			break
		}
	}

	// ip rule/route deletion — single command removes all matching
	_ = run("ip", "rule", "del", "fwmark", "1", "lookup", "100", "priority", "1000")
	_ = run("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "100")

	// SNAT masquerade (and DNS reply exception) — loop delete handles duplicates
	for _, subnet := range []string{r.lanSubnet} {
		for i := 0; i < 10; i++ {
			if err := run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-p", "udp", "--sport", "53", "-j", "ACCEPT"); err != nil {
				break
			}
		}
		for i := 0; i < 10; i++ {
			if err := run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"); err != nil {
				break
			}
		}
	}

	r.setup = false
	log.Info("network rules cleaned up")
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", strings.Join(append([]string{name}, args...), " "), err, string(out))
	}
	return nil
}
