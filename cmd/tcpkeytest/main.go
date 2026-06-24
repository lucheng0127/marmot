// Debug: manually write a TCP flow entry, then read it back,
// then check if eBPF can match it.
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/lucheng0127/marmot/pkg/bpf"
)

func main() {
	mgr := bpf.NewManager("br-test")
	result, err := mgr.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "LOAD ERR: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Unload()

	mgr.AddCIDR("192.168.100.0/24")
	mgr.Stats.Reset()

	clientIP := net.ParseIP("192.168.100.2")
	targetIP := net.ParseIP("203.0.113.50")

	// Write a TCP 4-tuple entry manually
	tcpOps := bpf.NewTCPFlowMapOps(result.TcpFlowMap)
	err = tcpOps.Put(bpf.TCPFlowKey{
		SrcIP:   clientIP,
		DstIP:   targetIP,
		DstPort: 8080,
	}, bpf.FlowValue{
		Action:   1, // proxy
		ExpireAt: uint32(time.Now().Unix()) + 3600,
	})
	if err != nil {
		fmt.Printf("PUT ERR: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("TCP ENTRY WRITTEN")

	// Read it back
	val, err := tcpOps.Get(bpf.TCPFlowKey{
		SrcIP:   clientIP,
		DstIP:   targetIP,
		DstPort: 8080,
	})
	if err != nil {
		fmt.Printf("GET ERR: %v\n", err)
	} else {
		fmt.Printf("READ BACK: action=%d expire=%d\n", val.Action, val.ExpireAt)
	}

	count, _ := tcpOps.Count()
	fmt.Printf("TCP ENTRIES: %d\n", count)

	// Now wait for traffic
	fmt.Println("Ready! Send: ip netns exec ns-client curl -m 2 http://203.0.113.50:8080/")
	fmt.Println("Then check flow_hit count")

	for i := 0; i < 10; i++ {
		time.Sleep(5 * time.Second)
		snap, _ := mgr.Stats.Read()
		fmt.Printf("[%ds] flow_hit=%d flow_miss=%d\n", (i+1)*5, snap.FlowHit, snap.FlowMiss)
		if snap.FlowHit > 0 {
			fmt.Println("*** FLOW HIT VERIFIED ***")
			break
		}
	}
}
