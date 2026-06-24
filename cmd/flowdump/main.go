// Flow dump — reads TCP/UDP flow entries from BPF maps
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

	tcpOps := bpf.NewTCPFlowMapOps(result.TcpFlowMap)
	tcpCount, _ := tcpOps.Count()
	fmt.Printf("TCP flow map entries: %d\n", tcpCount)

	udpOps := bpf.NewUDPFlowMapOps(result.UdpFlowMap)
	udpCount, _ := udpOps.Count()
	fmt.Printf("UDP flow map entries: %d\n", udpCount)

	stats, _ := mgr.Stats.Read()
	fmt.Print(stats.String())
}
