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
	log.Info("marmot BPF test starting", map[string]interface{}{
		"interface": *iface,
	})

	mgr := bpf.NewManager(*iface)
	result, err := mgr.Load()
	if err != nil {
		log.Error("failed to load BPF", map[string]interface{}{
			"error": err.Error(),
		})
		os.Exit(1)
	}
	log.Info("BPF loaded successfully")

	// Add some CIDR whitelist entries
	cidrs := []string{
		"192.168.100.0/24", // local bridge subnet
		"10.0.0.0/8",       // private
		"172.16.0.0/12",    // private
	}
	for _, cidr := range cidrs {
		if err := mgr.AddCIDR(cidr); err != nil {
			log.Warn("add CIDR failed", map[string]interface{}{
				"cidr":  cidr,
				"error": err.Error(),
			})
		} else {
			log.Info("CIDR added", map[string]interface{}{
				"cidr": cidr,
			})
		}
	}

	// Test verify: read stats
	snap, err := mgr.Stats.Read()
	if err != nil {
		log.Error("read stats failed", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		fmt.Println("\n=== Initial Stats ===")
		fmt.Print(snap.String())
	}

	// Print test instructions
	fmt.Println("\n=== Test Instructions ===")
	fmt.Println("Run in another terminal:")
	fmt.Printf("  # Test CIDR whitelist (should be DIRECT, no mark):\n")
	fmt.Printf("  ip netns exec ns-client ping -c 3 192.168.100.3\n")
	fmt.Printf("  # Test non-CIDR traffic (should get MARK):\n")
	fmt.Printf("  ip netns exec ns-client ping -c 3 8.8.8.8\n")
	fmt.Println("")
	fmt.Println("After running tests, check stats again (or press Ctrl+C to exit)")

	// Report stats every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

loop:
	for {
		select {
		case <-ticker.C:
			snap, err := mgr.Stats.Read()
			if err != nil {
				fmt.Printf("Stats error: %v\n", err)
				continue
			}
			fmt.Printf("\n--- %s ---\n", time.Now().Format("15:04:05"))
			fmt.Print(snap.String())
			if snap.TotalPackets > 0 {
				fmt.Printf("  cidr_hit_rate:  %.1f%%\n", float64(snap.CIDRHit)/float64(snap.TotalPackets)*100)
				fmt.Printf("  flow_hit_rate:  %.1f%%\n", float64(snap.FlowHit)/float64(snap.TotalPackets)*100)
				fmt.Printf("  proxy_mark_rate: %.1f%%\n", float64(snap.ProxyMark)/float64(snap.TotalPackets)*100)
			}

			// Check flow map entries
			flowOps := bpf.NewTCPFlowMapOps(result.TcpFlowMap)
			count, _ := flowOps.Count()
			fmt.Printf("  flow_map_entries: %d\n", count)

		case sig := <-sigCh:
			log.Info("received signal", map[string]interface{}{
				"signal": sig.String(),
			})
			break loop
		}
	}

	// Cleanup
	log.Info("unloading BPF")
	if err := mgr.Unload(); err != nil {
		log.Error("unload error", map[string]interface{}{
			"error": err.Error(),
		})
	}
	log.Info("BPF test complete")
}
