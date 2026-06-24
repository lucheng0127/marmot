// Flow Hit Verification via BPF Map Iteration
// Reads existing flow entries from BPF map to verify hit_count > 0
package main

import (
	"fmt"
	"os"

	"github.com/lucheng0127/marmot/pkg/bpf"
)

func main() {
	mgr := bpf.NewManager("br-test")
	result, err := mgr.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "BPF load: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Unload()

	// Read and display all flow entries
	flowOps := bpf.NewFlowMapOps(result.FlowMap)
	fmt.Println("=== Flow Map Entries ===")
	count := 0
	err = flowOps.Iterate(func(key bpf.FlowKey, value bpf.FlowValue) bool {
		count++
		fmt.Printf("Entry %d:\n", count)
		fmt.Printf("  SrcIP:   %s\n", key.SrcIP.String())
		fmt.Printf("  DstIP:   %s\n", key.DstIP.String())
		fmt.Printf("  SrcPort: %d\n", key.SrcPort)
		fmt.Printf("  DstPort: %d\n", key.DstPort)
		fmt.Printf("  Proto:   %d\n", key.Protocol)
		fmt.Printf("  Action:  %d (0=direct, 1=proxy)\n", value.Action)
		fmt.Printf("  HitCount: %d\n", value.HitCount)
		fmt.Printf("  ExpireAt: %d\n", value.ExpireAt)
		fmt.Println()
		return true
	})
	if err != nil {
		fmt.Printf("Iterate error: %v\n", err)
	}
	fmt.Printf("Total entries: %d\n", count)
}
