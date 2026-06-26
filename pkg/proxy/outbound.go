package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/include"
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

// AddNodeJSON adds a node from raw JSON bytes (properly parses nested options).
func (nm *NodeManager) AddNodeJSON(tag string, rawNode json.RawMessage) error {
	ctx := include.Context(context.Background())
	var outbound option.Outbound
	if err := outbound.UnmarshalJSONContext(ctx, rawNode); err != nil {
		return fmt.Errorf("parse node %s: %w", tag, err)
	}
	outbound.Tag = tag

	// Extract Server/ServerPort from the parsed raw node JSON
	// option.Outbound wraps these in Options field, so extract here
	var serverInfo struct {
		Server     string `json:"server"`
		ServerPort uint16 `json:"server_port"`
	}
	if serverErr := json.Unmarshal(rawNode, &serverInfo); serverErr == nil {
		nm.nodes[tag] = &Node{
			Tag:        tag,
			Type:       outbound.Type,
			Server:     serverInfo.Server,
			ServerPort: serverInfo.ServerPort,
			Options:    outbound,
			Healthy:    true,
		}
	} else {
		nm.nodes[tag] = &Node{
			Tag:     tag,
			Options: outbound,
			Healthy: true,
		}
	}
	log.Info("node added", map[string]interface{}{"tag": tag, "type": outbound.Type})
	return nil
}

// SetHealthy explicitly marks a node's health status.
func (nm *NodeManager) SetHealthy(tag string, healthy bool) {
	if node, ok := nm.nodes[tag]; ok {
		node.Healthy = healthy
		node.FailCount = 0
	}
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
