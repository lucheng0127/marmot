package config

import (
	"fmt"
	"os"

	"github.com/sagernet/sing-box/option"
	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure for marmot.
type Config struct {
	Log    LogConfig    `yaml:"log"`
	Proxy  ProxyConfig  `yaml:"proxy"`
	DNS    DNSConfig    `yaml:"dns"`
	TProxy TProxyConfig `yaml:"tproxy"`
	BPF    BPFConfig    `yaml:"bpf"`
	API    APIConfig    `yaml:"api"`
	Rules  []RuleConfig `yaml:"rules"`
}

// LogConfig defines logging configuration.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
	Output string `yaml:"output"` // stdout, stderr, file path
}

// ProxyConfig defines upstream proxy node groups.
type ProxyConfig struct {
	Groups []ProxyGroup `yaml:"groups"`
	Nodes  map[string]option.Outbound `yaml:"nodes"` // tag -> outbound option
}

// ProxyGroup is a named group of proxy nodes sharing the same outbound tag.
type ProxyGroup struct {
	Tag   string      `yaml:"tag"`
	Nodes []ProxyNode `yaml:"nodes"`
}

// ProxyNode defines a single proxy upstream node.
type ProxyNode struct {
	Name     string `yaml:"name"`
	Protocol string `yaml:"protocol"` // shadowsocks, vmess, vless, trojan
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	Cipher   string `yaml:"cipher,omitempty"`
	Password string `yaml:"password,omitempty"`
	UUID     string `yaml:"uuid,omitempty"`
	AlterID  int    `yaml:"alter_id,omitempty"`
	Network  string `yaml:"network,omitempty"` // tcp, kcp, ws, quic
	TLS      bool   `yaml:"tls,omitempty"`
	Flow     string `yaml:"flow,omitempty"` // vless flow control
}

// DNSConfig defines DNS subsystem configuration.
type DNSConfig struct {
	Listen      string        `yaml:"listen"`       // listener address for LAN clients
	LocalListen string        `yaml:"local_listen"` // 127.0.0.1:53 for gateway itself
	Upstreams   []DNSUpstream `yaml:"upstreams"`
	CacheSize   int           `yaml:"cache_size"`
}

// DNSUpstream defines a single DNS upstream server.
type DNSUpstream struct {
	Tag      string `yaml:"tag"`
	Protocol string `yaml:"protocol"` // udp, tcp, doh, dot
	Addr     string `yaml:"addr"`
}

// TProxyConfig defines TProxy listener configuration.
type TProxyConfig struct {
	TCPAddr      string `yaml:"tcp_addr"`       // e.g. :1080
	UDPAddr      string `yaml:"udp_addr"`       // e.g. :1080
	OutboundAddr string `yaml:"outbound_addr"`  // e.g. 127.0.0.1:10800 (Xray dokodemo-door)
}

// BPFConfig defines eBPF program configuration.
type BPFConfig struct {
	Interface     string   `yaml:"interface"`      // bridge interface name (br0)
	CIDRWhitelist []string `yaml:"cidr_whitelist"` // CIDR entries for direct bypass
}

// APIConfig defines HTTP API server configuration.
type APIConfig struct {
	Listen string `yaml:"listen"` // e.g. :8080
	Enable bool   `yaml:"enable"`
	Auth   string `yaml:"auth,omitempty"`
}

// RuleConfig defines a single routing rule.
type RuleConfig struct {
	Type   string     `yaml:"type"`  // domain, domain_suffix, domain_keyword, ip, geoip, geosite, default
	Match  string     `yaml:"match"` // match value
	Action RuleAction `yaml:"action"`
}

// RuleAction defines what to do when a rule matches.
type RuleAction struct {
	Mode string `yaml:"mode"` // direct, proxy, block, dns_upstream
	Tag  string `yaml:"tag,omitempty"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Log: LogConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
		TProxy: TProxyConfig{
			TCPAddr: ":1080",
			UDPAddr: ":1080",
		},
		DNS: DNSConfig{
			Listen:      ":53",
			LocalListen: "127.0.0.1:53",
			CacheSize:   4096,
			Upstreams: []DNSUpstream{
				{Tag: "domestic", Protocol: "udp", Addr: "114.114.114.114:53"},
				{Tag: "oversea", Protocol: "doh", Addr: "https://1.1.1.1/dns-query"},
			},
		},
		BPF: BPFConfig{
			Interface: "br0",
			CIDRWhitelist: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"127.0.0.0/8",
			},
		},
		API: APIConfig{
			Listen: ":8080",
			Enable: false,
		},
	}
}

// Load reads a YAML config file and returns the parsed Config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	return cfg, nil
}

// Reload re-reads config from disk and returns a new Config.
// This is used for hot-reload; the caller should swap the old config atomically.
func Reload(path string) (*Config, error) {
	return Load(path)
}
