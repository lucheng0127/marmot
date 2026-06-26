// Flow Learning Verification — Phase 2 simplified
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

	// 1. Load eBPF (CIDR + fwmark only)
	mgr := bpf.NewManager(*iface)
	result, err := mgr.Load()
	if err != nil {
		log.Error("BPF load failed", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	defer mgr.Unload()
	mgr.AddCIDR("192.168.100.0/24")
	_ = result

	// 2. Create Decision Cache (pure target key)
	cache := conntrack.New(1*time.Hour, 65536)

	// 3. Decision Interface + TProxy
	decider := tproxy.NewStaticDecider()
	var nilDial tproxy.DialFunc
	listener := tproxy.NewListener(*tproxyAddr, decider, cache, nilDial)
	if err := listener.Start(); err != nil {
		log.Error("TProxy start failed", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("\n========================================")
	fmt.Println("Phase 2 — TProxy + Decision Cache")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Send traffic:")
	fmt.Println("  ip netns exec ns-client curl -m 3 http://203.0.113.1:8080/")
	fmt.Println()

	// Stats display loop
	ticker := time.NewTicker(3 * time.Second)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	prevStats, _ := mgr.Stats.Read()
	prevCacheCount := 0

loop:
	for {
		select {
		case <-ticker.C:
			snap, _ := mgr.Stats.Read()
			cacheCount, _ := cache.Stats()

			fmt.Printf("\n--- %s ---\n", time.Now().Format("15:04:05"))
			fmt.Print(snap.String())
			fmt.Printf("  cache_entries: %d\n", cacheCount)

			if snap.ProxyMark > prevStats.ProxyMark {
				delta := snap.ProxyMark - prevStats.ProxyMark
				fmt.Printf("  >>> Traffic detected: +%d packets marked <<<\n", delta)
			}
			if cacheCount > prevCacheCount {
				fmt.Printf("  >>> Decision Cache entry added: now %d entries <<<\n", cacheCount)
			}
			prevStats = snap
			prevCacheCount = cacheCount

		case sig := <-sigCh:
			log.Info("signal", map[string]interface{}{"signal": sig.String()})
			break loop
		}
	}

	log.Info("test complete")
}

var _ = net.IPv4
