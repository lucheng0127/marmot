// Investigation: CIDR Whitelist + Bridge Path
//
// Tests:
//  1. LPM_TRIE Write → Read Back  (Go ↔ BPF Map correct?)
//  2. CIDR Match on bridge IP ping (locally destined)
//  3. CIDR Match on bridge forward (L2 bridged)
//  4. CIDR Match on veth slave port attach
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lucheng0127/marmot/pkg/bpf"
	"github.com/lucheng0127/marmot/pkg/log"
)

func main() {
	iface := flag.String("iface", "br-test", "interface to attach BPF")
	flag.Parse()

	log.Init(log.DebugLevel, "text", "stdout")

	// ── Step 1: Load BPF ──
	log.Info("1. Loading BPF on", map[string]interface{}{"iface": *iface})
	mgr := bpf.NewManager(*iface)
	result, err := mgr.Load()
	if err != nil {
		log.Error("LOAD FAILED", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	log.Info("LOAD OK")

	// ── Step 2: Write CIDR entry ──
	log.Info("2. Writing CIDR entry 192.168.100.0/24")
	if err := mgr.AddCIDR("192.168.100.0/24"); err != nil {
		log.Error("CIDR WRITE FAILED", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	log.Info("CIDR WRITE OK")

	// ── Step 3: Read CIDR entry back ──
	log.Info("3. Reading CIDR entry back")
	// Manually construct the LPM_TRIE key for 192.168.100.0/24 and look it up
	lookupKey := bpf.MarmotCidrKey{
		Prefixlen: 24,
		Prefix:    [4]uint8{192, 168, 100, 0},
	}
	var lookupVal bpf.MarmotCidrValue
	if err := result.CidrWhitelist.Lookup(&lookupKey, &lookupVal); err != nil {
		log.Error("CIDR READ BACK FAILED", map[string]interface{}{"error": err.Error()})
	} else {
		log.Info("CIDR READ BACK OK", map[string]interface{}{"action": lookupVal.Action})
	}

	// Also try with a different IP in the same /24 to prove LPM matching
	lookupKey2 := bpf.MarmotCidrKey{
		Prefixlen: 32,
		Prefix:    [4]uint8{192, 168, 100, 55},
	}
	var lookupVal2 bpf.MarmotCidrValue
	if err := result.CidrWhitelist.Lookup(&lookupKey2, &lookupVal2); err != nil {
		log.Error("LPM MATCH (192.168.100.55/32) FAILED", map[string]interface{}{"error": err.Error()})
	} else {
		log.Info("LPM MATCH OK", map[string]interface{}{"action": lookupVal2.Action})
	}

	// Try with an IP outside the CIDR to verify non-match
	lookupKey3 := bpf.MarmotCidrKey{
		Prefixlen: 32,
		Prefix:    [4]uint8{8, 8, 8, 8},
	}
	var lookupVal3 bpf.MarmotCidrValue
	if err := result.CidrWhitelist.Lookup(&lookupKey3, &lookupVal3); err != nil {
		log.Info("NON-MATCH EXPECTED (8.8.8.8/32)", map[string]interface{}{"error": err.Error()})
	} else {
		log.Error("NON-MATCH SHOULD HAVE FAILED", map[string]interface{}{"action": lookupVal3.Action})
	}

	// ── Step 4: Reset stats and wait for traffic tests ──
	mgr.Stats.Reset()

	fmt.Println("\n============================================")
	fmt.Println("INVESTIGATION READY — Run traffic tests now")
	fmt.Println("============================================")
	fmt.Println()
	fmt.Println("Test A: Ping bridge IP (locally destined)")
	fmt.Println("  ip netns exec ns-client ping -c 3 192.168.100.1")
	fmt.Println()
	fmt.Println("Test B: Ping bridge L2 forward")
	fmt.Println("  ip netns exec ns-client ping -c 3 192.168.100.3")
	fmt.Println()
	fmt.Println("Test C: Ping external (non-CIDR)")
	fmt.Println("  ip netns exec ns-client ping -c 2 -W 1 8.8.8.8")
	fmt.Println()

	// Wait, then report stats
	time.Sleep(5 * time.Second)

	snap, _ := mgr.Stats.Read()
	fmt.Println("\n=== STATS ===")
	fmt.Print(snap.String())
	fmt.Printf("  flow_map_entries: %d\n", func() int { c, _ := bpf.NewTCPFlowMapOps(result.TcpFlowMap).Count(); return c }())

	// Now check again after 10 more seconds (user runs tests)
	fmt.Println("\nWaiting 30s for traffic tests...")
	fmt.Println("Run the test commands now in another terminal!")

	ticker := time.NewTicker(10 * time.Second)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

loop:
	for {
		select {
		case <-ticker.C:
			snap, _ := mgr.Stats.Read()
			fmt.Printf("\n--- %s ---\n", time.Now().Format("15:04:05"))
			fmt.Print(snap.String())
			if snap.CIDRHit > 0 || snap.FlowMiss > 0 || snap.FlowHit > 0 {
				fmt.Println(">>> TRAFFIC DETECTED <<<")
			}
			if snap.CIDRHit > 0 {
				fmt.Println("*** CIDR WHITELIST WORKING ***")
			}
		case <-sigCh:
			break loop
		}
	}

	// Final report
	snap, _ = mgr.Stats.Read()
	fmt.Println("\n=== FINAL STATS ===")
	fmt.Print(snap.String())

	mgr.Unload()
	log.Info("Investigation complete")
}
