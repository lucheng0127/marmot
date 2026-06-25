// Package netif automates iptables + iproute2 setup/cleanup for TProxy and DNS.
package netif

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/lucheng0127/marmot/pkg/log"
)

// Rules manages the lifecycle of network rules.
type Rules struct {
	setup bool
}

func New() *Rules { return &Rules{} }

// Setup configures policy routing, iptables TPROXY, and DNS REDIRECT.
func (r *Rules) Setup() error {
	cmds := [][]string{
		// Policy routing: fwmark=1 -> localhost (table 100)
		{"ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100"},
		{"ip", "rule", "add", "fwmark", "1", "lookup", "100", "priority", "1000"},

		// iptables mangle: TPROXY chain
		{"iptables", "-t", "mangle", "-N", "MARMOT_TPROXY"},
		{"iptables", "-t", "mangle", "-A", "PREROUTING", "-m", "mark", "--mark", "1", "-j", "MARMOT_TPROXY"},
		{"iptables", "-t", "mangle", "-A", "MARMOT_TPROXY", "-p", "tcp", "-j", "TPROXY", "--on-port", "1080", "--on-ip", "127.0.0.1"},
		{"iptables", "-t", "mangle", "-A", "MARMOT_TPROXY", "-p", "udp", "-j", "TPROXY", "--on-port", "1080", "--on-ip", "127.0.0.1"},

		// DNS transparent hijack
		{"iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"},
	}

	for _, args := range cmds {
		if err := run(args[0], args[1:]...); err != nil {
			// Some rules may already exist (e.g. after restart) — log but continue
			log.Debug("net rule (may already exist)", map[string]interface{}{
				"cmd":   strings.Join(args, " "),
				"error": err.Error(),
			})
		}
	}

	r.setup = true
	log.Info("network rules configured")
	return nil
}

// Cleanup removes all rules added by Setup().
func (r *Rules) Cleanup() error {
	if !r.setup {
		return nil
	}

	cmds := [][]string{
		// Clean up TPROXY chain
		{"iptables", "-t", "mangle", "-D", "PREROUTING", "-m", "mark", "--mark", "1", "-j", "MARMOT_TPROXY"},
		{"iptables", "-t", "mangle", "-F", "MARMOT_TPROXY"},
		{"iptables", "-t", "mangle", "-X", "MARMOT_TPROXY"},

		// Clean up DNS REDIRECT
		{"iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"},

		// Clean up policy routing
		{"ip", "rule", "del", "fwmark", "1", "lookup", "100", "priority", "1000"},
		{"ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "100"},
	}

	for _, args := range cmds {
		_ = run(args[0], args[1:]...) // ignore errors on cleanup
	}

	r.setup = false
	log.Info("network rules cleaned up")
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, string(out))
	}
	return nil
}
