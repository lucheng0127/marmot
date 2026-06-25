// Package netif automates iptables + iproute2 setup/cleanup.
// All operations are IDEMPOTENT: safe to call multiple times.
package netif

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/lucheng0127/marmot/pkg/log"
)

type Rules struct{ setup bool }

func New() *Rules { return &Rules{} }

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
	log.Info("network rules configured")
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
