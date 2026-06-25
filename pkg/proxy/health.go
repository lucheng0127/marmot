package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
)

// HealthChecker periodically checks node availability.
type HealthChecker struct {
	nm        *NodeManager
	interval  time.Duration
	timeout   time.Duration
}

func NewHealthChecker(nm *NodeManager, interval, timeout time.Duration) *HealthChecker {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HealthChecker{
		nm:       nm,
		interval: interval,
		timeout:  timeout,
	}
}

// Start launches background health checks.
func (hc *HealthChecker) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(hc.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				hc.checkAll()
			case <-ctx.Done():
				return
			}
		}
	}()
	log.Info("health checker started", map[string]interface{}{
		"interval": hc.interval.String(),
	})
}

// checkAll runs health checks on all nodes.
func (hc *HealthChecker) checkAll() {
	for _, node := range hc.nm.nodes {
		healthy := hc.ping(node)
		now := time.Now()
		node.LastCheck = now
		if healthy {
			node.FailCount = 0
			if !node.Healthy {
				log.Info("node recovered", map[string]interface{}{
					"tag": node.Tag,
				})
			}
			node.Healthy = true
		} else {
			node.FailCount++
			if node.FailCount >= 3 {
				node.Healthy = false
				log.Warn("node marked unhealthy", map[string]interface{}{
					"tag":  node.Tag,
					"fails": node.FailCount,
				})
			}
		}
	}
}

// ping tests a node by attempting a TCP connection.
func (hc *HealthChecker) ping(node *Node) bool {
	addr := net.JoinHostPort(node.Server, fmt.Sprintf("%d", node.ServerPort))
	conn, err := net.DialTimeout("tcp", addr, hc.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
