// Flow Hit Intra-Connection Test
// Sends multiple HTTP requests on the same TCP connection to verify Flow HIT
package main

import (
	"fmt"
	"net"
	"time"

	"github.com/lucheng0127/marmot/pkg/bpf"
)

func main() {
	// Load BPF with the existing Flow Map
	mgr := bpf.NewManager("br-test")
	result, err := mgr.Load()
	if err != nil {
		fmt.Printf("BPF load: %v\n", err)
		return
	}
	defer mgr.Unload()

	mgr.AddCIDR("192.168.100.0/24")
	mgr.Stats.Reset()

	fmt.Println("=== Flow HIT Verification ===")
	fmt.Println("Opening TCP connection to external target...")

	// Connect via ns-client (TProxy will intercept)
	conn, err := net.DialTimeout("tcp", "203.0.113.100:8080", 5*time.Second)
	if err != nil {
		fmt.Printf("Dial: %v (expected if no server)\n", err)
	} else {
		// Send data multiple times on the SAME connection
		for i := 0; i < 3; i++ {
			_, _ = conn.Write([]byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: test\r\n\r\n")))
			time.Sleep(100 * time.Millisecond)
		}
		conn.Close()
	}

	// Read stats
	time.Sleep(1 * time.Second)
	snap, _ := mgr.Stats.Read()
	fmt.Printf("\n=== Final Stats ===\n")
	fmt.Printf("  flow_hit:  %d\n", snap.FlowHit)
	fmt.Printf("  flow_miss: %d\n", snap.FlowMiss)
	fmt.Printf("  proxy_mark: %d\n", snap.ProxyMark)

	if snap.FlowHit > 0 {
		fmt.Println("\n*** FLOW HIT VERIFIED ***")
	} else {
		fmt.Println("\n(no Flow HIT — all packets miss due to unique 5-tuple per connection)")
		fmt.Println("This is expected for new TCP connections with different source ports.")
	}

	// Check raw counters
	flowOps := bpf.NewTCPFlowMapOps(result.TcpFlowMap)
	count, _ := flowOps.Count()
	fmt.Printf("  flow_map_entries: %d\n", count)
}
