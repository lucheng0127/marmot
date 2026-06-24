// Flow Learning Verification Tool
// Tests: FlowMiss → Decision → Writeback → FlowHit
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lucheng0127/marmot/pkg/bpf"
	"github.com/lucheng0127/marmot/pkg/conntrack"
	"github.com/lucheng0127/marmot/pkg/log"
	"github.com/lucheng0127/marmot/pkg/tproxy"
)

func main() {
	iface := flag.String("iface", "br-test", "interface for BPF attach")
	tproxyAddr := flag.String("tproxy", ":1080", "TProxy listen address")
	flag.Parse()

	log.Init(log.DebugLevel, "text", "stdout")

	// 1. Load BPF
	log.Info("1. Loading eBPF")
	mgr := bpf.NewManager(*iface)
	result, err := mgr.Load()
	if err != nil {
		log.Error("BPF load failed", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	defer mgr.Unload()
	log.Info("BPF loaded")

	// 2. Add CIDR whitelist
	mgr.AddCIDR("192.168.100.0/24")
	log.Info("CIDR whitelist added")

	// 3. Create Conntrack Cache
	ctCache := conntrack.New(1*time.Hour, 65536)

	// 4. Create SyncManager + connect to BPF Flow Map
	ctSync := conntrack.NewSyncManager(result.FlowMap, ctCache)
	ctSync.Connect()
	log.Info("Flow Map sync connected")

	// 5. Create Decision Interface + TProxy
	decider := tproxy.NewStaticDecider()
	tpListener := tproxy.NewListener(*tproxyAddr, decider, ctCache)
	if err := tpListener.Start(); err != nil {
		log.Error("TProxy start failed", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	log.Info("TProxy listening", map[string]interface{}{"addr": *tproxyAddr})

	// 6. Reset stats
	mgr.Stats.Reset()

	fmt.Println("\n========================================")
	fmt.Println("Flow Learning Verification")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Step 1: Send FIRST request to external IP")
	fmt.Println("  ip netns exec ns-client curl -m 3 http://198.51.100.1:8080/ 2>&1 | head -2")
	fmt.Println("  (expect: connection reset or timeout == Flow Cache MISS → TProxy)")
	fmt.Println()
	fmt.Println("Step 2: Check Flow Cache Writeback")
	fmt.Println("  (verify BPF Flow Map has entry)")
	fmt.Println()
	fmt.Println("Step 3: Send SECOND request to SAME target")
	fmt.Println("  ip netns exec ns-client curl -m 3 http://198.51.100.1:8080/ 2>&1 | head -2")
	fmt.Println("  (expect: Flow Cache HIT → TC mark → TProxy)")
	fmt.Println()

	// Report loop
	ticker := time.NewTicker(3 * time.Second)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	prevStats, _ := mgr.Stats.Read()

loop:
	for {
		select {
		case <-ticker.C:
			snap, _ := mgr.Stats.Read()
			flowCount, _ := bpf.NewFlowMapOps(result.FlowMap).Count()

			fmt.Printf("\n--- %s ---\n", time.Now().Format("15:04:05"))
			fmt.Print(snap.String())
			fmt.Printf("  flow_map_entries: %d\n", flowCount)
			fmt.Printf("  conntrack_cache:  %d\n", ctCache.Count())

			// Detect Flow Learning
			if snap.FlowMiss > prevStats.FlowMiss {
				fmt.Printf("  >>> FlowCacheMISS detected (+%d) <<<\n", snap.FlowMiss-prevStats.FlowMiss)
			}
			if flowCount > 0 && snap.FlowHit == 0 {
				fmt.Println("  Flow written to BPF Map - ready for HIT test")
			}
			if snap.FlowHit > prevStats.FlowHit {
				fmt.Printf("  >>> FlowCacheHIT detected (+%d) <<< 🎉\n", snap.FlowHit-prevStats.FlowHit)
				fmt.Println("  *** FLOW LEARNING VERIFIED ***")
			}
			prevStats = snap

		case sig := <-sigCh:
			log.Info("signal received", map[string]interface{}{"signal": sig.String()})
			break loop
		}
	}

	tpListener.Close()
	log.Info("test complete")
}

// Ensure net is used
var _ = net.IPv4
