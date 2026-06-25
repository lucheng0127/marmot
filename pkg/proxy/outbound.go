package proxy

import (
	"fmt"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
	"github.com/sagernet/sing-box/option"
)

// Node represents a single proxy outbound node.
type Node struct {
	Tag       string
	Type      string // shadowsocks, vmess, vless, trojan, hysteria2, wireguard, tuic
	Server    string
	ServerPort uint16
	// Protocol-specific fields stored in Options
	Options option.Outbound

	Healthy    bool
	LastCheck  time.Time
	FailCount  int
}

// NodeManager manages the pool of proxy nodes.
type NodeManager struct {
	nodes map[string]*Node // tag -> Node
}

func NewNodeManager() *NodeManager {
	return &NodeManager{
		nodes: make(map[string]*Node),
	}
}

// AddNode adds a node to the pool.
func (nm *NodeManager) AddNode(tag string, outbound option.Outbound) {
	nm.nodes[tag] = &Node{
		Tag:     tag,
		Options: outbound,
		Healthy: true,
	}
	log.Info("node added", map[string]interface{}{
		"tag":  tag,
		"type": outbound.Type,
	})
}

// RemoveNode removes a node from the pool.
func (nm *NodeManager) RemoveNode(tag string) {
	delete(nm.nodes, tag)
}

// GetNode returns a node by tag.
func (nm *NodeManager) GetNode(tag string) (*Node, error) {
	n, ok := nm.nodes[tag]
	if !ok {
		return nil, fmt.Errorf("node not found: %s", tag)
	}
	return n, nil
}

// ListNodes returns all nodes.
func (nm *NodeManager) ListNodes() []*Node {
	var nodes []*Node
	for _, n := range nm.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// Count returns the number of nodes.
func (nm *NodeManager) Count() int {
	return len(nm.nodes)
}
