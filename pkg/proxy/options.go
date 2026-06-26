package proxy

import (
	"fmt"
	"net/url"
	"sort"

	"github.com/sagernet/sing-box/option"
)

// OptionsConverter converts Marmot config into sing-box options.
// Per ADR-003: only outbound configuration is passed to sing-box.
// Inbound (TProxy) is handled by Marmot.
type OptionsConverter struct{}

func NewOptionsConverter() *OptionsConverter {
	return &OptionsConverter{}
}

// ToOptions builds sing-box option.Options from a list of outbound tags.
// Returns the options and the ordered list of node tags.
func (c *OptionsConverter) ToOptions(nm *NodeManager) (option.Options, []string) {
	var outbounds []option.Outbound
	var tags []string

	// Collect and sort tags for deterministic ordering
	for tag := range nm.nodes {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	// Add each node as an outbound, sorted by tag
	for _, tag := range tags {
		node := nm.nodes[tag]
		o := node.Options
		o.Tag = tag
		outbounds = append(outbounds, o)
	}

	// Add a direct outbound as fallback
	outbounds = append(outbounds, option.Outbound{
		Tag:  "direct",
		Type: "direct",
	})

	// Set first node as final (default), fallback to direct
	finalTag := "direct"
	if len(tags) > 0 {
		finalTag = tags[0]
	}

	return option.Options{
		Log: &option.LogOptions{
			Disabled: false,
			Level:    "warn",
		},
		Inbounds:  []option.Inbound{},
		Outbounds: outbounds,
		Route: &option.RouteOptions{
			Final: finalTag,
		},
	}, tags
}

// ParseProxyURL parses a proxy URL into an outbound option.
func ParseProxyURL(proxyURL string) (option.Outbound, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return option.Outbound{}, fmt.Errorf("parse proxy URL: %w", err)
	}

	var outbound option.Outbound
	switch u.Scheme {
	case "ss":
		outbound.Type = "shadowsocks"
	case "vmess":
		outbound.Type = "vmess"
	case "vless":
		outbound.Type = "vless"
	case "trojan":
		outbound.Type = "trojan"
	default:
		return option.Outbound{}, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}

	outbound.Tag = "proxy-" + u.Scheme
	return outbound, nil
}
