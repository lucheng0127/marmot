package main

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/lucheng0127/marmot/pkg/netif"
)

func main() {
	r := netif.New()

	// 1. First setup
	fmt.Println("=== SETUP 1 ===")
	r.Setup()
	check("after setup 1")

	// 2. Second setup (idempotent)
	fmt.Println("\n=== SETUP 2 (should not duplicate) ===")
	r.Setup()
	check("after setup 2")

	// 3. Cleanup
	fmt.Println("\n=== CLEANUP ===")
	r.Cleanup()
	check("after cleanup")

	// 4. Second cleanup (should be safe)
	fmt.Println("\n=== CLEANUP 2 (should be safe) ===")
	r.Cleanup()
	fmt.Println("OK: second cleanup completed")
}

func check(label string) {
	// Count ip rules
	rules := run("ip", "rule", "show")
	rulesCnt := strings.Count(rules, "fwmark 0x1 lookup 100")
	
	// Count TPROXY rules
	tproxy := run("iptables", "-t", "mangle", "-L", "MARMOT_TPROXY", "-n")
	tproxyCnt := strings.Count(tproxy, "TPROXY")
	
	// Count DNS rules
	nat := run("iptables", "-t", "nat", "-L", "PREROUTING", "-n")
	dnsCnt := strings.Count(nat, "udp dpt:53 redir ports 53")

	fmt.Printf("[%s] fwmark=%d tproxy=%d dns=%d\n", label, rulesCnt, tproxyCnt, dnsCnt)
	if rulesCnt > 1 || tproxyCnt > 2 || dnsCnt > 1 {
		fmt.Printf("  WARNING: duplicates detected! rules=%d tproxy=%d dns=%d\n", rulesCnt, tproxyCnt, dnsCnt)
	}
}

func run(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
}
