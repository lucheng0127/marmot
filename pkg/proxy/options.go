package proxy

import (
	"fmt"
	"net/url"

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
func (c *OptionsConverter) ToOptions(nm *NodeManager) option.Options {
	var outbounds []option.Outbound

	// Add each node as an outbound
	for _, node := range nm.nodes {
		o := node.Options
		o.Tag = node.Tag
		outbounds = append(outbounds, o)
	}

	// Add a direct outbound as fallback
	outbounds = append(outbounds, option.Outbound{
		Tag:  "direct",
		Type: "direct",
	})

	// Set the first node as final (default) outbound, fallback to direct
	finalTag := "direct"
	for _, node := range nm.nodes {
		finalTag = node.Tag
		break
	}

	return option.Options{
		Log: &option.LogOptions{
			Disabled: true,
			Level:    "warn",
		},
		Inbounds:  []option.Inbound{},
		Outbounds: outbounds,
		Route: &option.RouteOptions{
			Final: finalTag,
		},
	}
}

// ParseProxyURL parses a proxy URL into an outbound option.
// Supports formats like:
//
//	ss://method:password@server:port
//	vmess://...
//	vless://...
//	trojan://password@server:port
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
		return option.Outbound{}, fmt.Errorf("unsupported proxy type: %s", u.Scheme)
	}

	outbound.Tag = u.Scheme + "-" + u.Host
	return outbound, nil
}
