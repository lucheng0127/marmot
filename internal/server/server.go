package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lucheng0127/marmot/internal/config"
	"github.com/lucheng0127/marmot/pkg/bpf"
	"github.com/lucheng0127/marmot/pkg/conntrack"
	"github.com/lucheng0127/marmot/pkg/dns"
	"github.com/lucheng0127/marmot/pkg/geo"
	"github.com/lucheng0127/marmot/pkg/log"
	"github.com/lucheng0127/marmot/pkg/netif"
	"github.com/lucheng0127/marmot/pkg/proxy"
	"github.com/lucheng0127/marmot/pkg/rule"
	"github.com/lucheng0127/marmot/pkg/tproxy"
)

type Server struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc

	bpfMgr  *bpf.Manager
	tproxy  *tproxy.Listener
	udpTpr  *tproxy.UDPListener
	decider tproxy.Decider
	cache   *conntrack.Cache

	flowWriter *bpf.FlowWriter
	netRules   *netif.Rules  // Phase 6: network automation

	proxyEngine *proxy.Engine
	nodeMgr     *proxy.NodeManager
	healthChk   *proxy.HealthChecker
	optsConv    *proxy.OptionsConverter

	// Phase 5: Rule Engine
	ruleEngine *rule.Engine
	geoReader  *geo.Reader

	// Phase 4: DNS
	dnsServer *dns.Server
	dnsEngine *dns.Engine
	dnsCache  *dns.Cache
	dnsUpMgr  *dns.UpstreamManager
}

func New(cfg *config.Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{cfg: cfg, ctx: ctx, cancel: cancel}
}

func (s *Server) Run() error {
	log.Info("initializing Phase 5 subsystems")

	// 0. Network rules automation (Phase 6.1)
	s.netRules = netif.New()
	if err := s.netRules.Setup(); err != nil {
		return err
	}

	// 1. eBPF (with Flow Cache maps)
	s.bpfMgr = bpf.NewManager(s.cfg.BPF.Interface)
	result, err := s.bpfMgr.Load()
	if err != nil {
		return err
	}
	for _, cidr := range s.cfg.BPF.CIDRWhitelist {
		_ = s.bpfMgr.AddCIDR(cidr)
	}

	// 2. Flow Writer (writeback to eBPF Flow Cache)
	s.flowWriter = bpf.NewFlowWriter(result.TcpFlowMap, result.UdpFlowMap)

	// 3. Decision Cache
	s.cache = conntrack.New(1*time.Hour, 65536)
	s.cache.StartGC(5*time.Minute, make(chan struct{}))

	// 4. GeoIP Reader (Phase 5)
	s.geoReader = geo.NewReader(s.cfg.Rule.GeoIPPath, s.cfg.Rule.GeoSitePath)

	// 5. Rule Engine (Phase 5)
	s.ruleEngine = rule.NewEngine(s.geoReader)
	if err := s.ruleEngine.LoadRules(configToRuleConfigs(s.cfg.Rules)); err != nil {
		log.Warn("rule loading", map[string]interface{}{"error": err.Error()})
	}

	// 6. Decision Interface — Rule Engine Decider
	s.decider = tproxy.NewRuleEngineDecider(s.ruleEngine)

	// 7. Node Manager
	s.nodeMgr = proxy.NewNodeManager()
	for tag, nodeCfg := range s.cfg.Proxy.Nodes {
		s.nodeMgr.AddNode(tag, nodeCfg)
	}

	// 5. sing-box Engine
	s.optsConv = proxy.NewOptionsConverter()
	options := s.optsConv.ToOptions(s.nodeMgr)
	s.proxyEngine, err = proxy.New(s.ctx, options)
	if err != nil {
		return err
	}
	if err := s.proxyEngine.Start(); err != nil {
		return err
	}

	// 6. TCP TProxy (direct dial through sing-box engine, no SOCKS5)
	s.tproxy = tproxy.NewListener(s.cfg.TProxy.TCPAddr, s.decider, s.cache,
		func(network, addr string) (net.Conn, error) {
			return s.proxyEngine.DialTimeout(network, addr, 30*time.Second)
		})
	if err := s.tproxy.Start(); err != nil {
		return err
	}

	// 7. UDP TProxy
	s.udpTpr = tproxy.NewUDPListener(s.cfg.TProxy.UDPAddr, s.decider, s.cache, "127.0.0.1:10800")
	if err := s.udpTpr.Start(); err != nil {
		return err
	}

	// 8. Health Checker
	s.healthChk = proxy.NewHealthChecker(s.nodeMgr, 30*time.Second, 5*time.Second)
	s.healthChk.Start(s.ctx)

	// ── Phase 4: DNS Subsystem ──

	// 9. DNS Cache
	ttl := time.Duration(s.cfg.DNS.CacheTTL) * time.Second
	if ttl <= 0 {
		ttl = 300 * time.Second
	}
	cacheSize := s.cfg.DNS.CacheSize
	if cacheSize <= 0 {
		cacheSize = 1024
	}
	s.dnsCache = dns.NewCache(cacheSize, ttl)

	// 10. Build Upstream Configs
	upstreams := configToUpstreams(s.cfg.DNS.Upstreams)
	if len(upstreams) == 0 {
		upstreams = dns.DefaultUpstreams()
	}

	// 11. DNS Engine (with Rule Engine + Flow Cache writeback)
	s.dnsEngine = dns.NewEngine(upstreams, s.dnsCache, s.ruleEngine, s.flowWriter)

	// 12. Upstream Manager
	s.dnsUpMgr = dns.NewUpstreamManager(upstreams, s.dnsEngine)

	// 13. DNS Server
	dnsAddr := s.cfg.DNS.Listen
	if dnsAddr == "" {
		dnsAddr = ":53"
	}
	s.dnsServer = dns.NewServer(dnsAddr, s.dnsEngine)
	if err := s.dnsServer.Start(); err != nil {
		return err
	}

	log.Info("marmot is running (Phase 5: Rule Engine + eBPF Flow Cache)")
	log.Info("waiting for signal")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	select {
	case sig := <-sigCh:
		log.Info("received signal", map[string]interface{}{"signal": sig.String()})
		if sig == syscall.SIGHUP {
			return s.reload()
		}
	case <-s.ctx.Done():
	}
	return s.Shutdown()
}

// reload handles SIGHUP — reloads config, rules, and restarts subsystems.
func (s *Server) reload() error {
	log.Info("SIGHUP received — reloading configuration")

	// Reload config from file
	cfg, err := config.Load(s.cfg.ConfigPath)
	if err != nil {
		return fmt.Errorf("reload config: %w", err)
	}
	s.cfg = cfg

	// Reload Geo databases
	if s.geoReader != nil {
		_ = s.geoReader.ReloadGeoIP()
	}

	// Reload rules
	s.ruleEngine = rule.NewEngine(s.geoReader)
	if err := s.ruleEngine.LoadRules(configToRuleConfigs(s.cfg.Rules)); err != nil {
		log.Warn("reload rules", map[string]interface{}{"error": err.Error()})
	}

	// Update Decision Interface
	s.decider = tproxy.NewRuleEngineDecider(s.ruleEngine)

	// Update DNS engine
	upstreams := configToUpstreams(s.cfg.DNS.Upstreams)
	if len(upstreams) == 0 {
		upstreams = dns.DefaultUpstreams()
	}
	s.dnsEngine = dns.NewEngine(upstreams, s.dnsCache, s.ruleEngine, s.flowWriter)
	if s.dnsUpMgr != nil {
		s.dnsUpMgr.Reload(upstreams)
	}

	// Restart DNS server
	if s.dnsServer != nil {
		s.dnsServer.Close()
	}
	dnsAddr := s.cfg.DNS.Listen
	if dnsAddr == "" {
		dnsAddr = ":53"
	}
	s.dnsServer = dns.NewServer(dnsAddr, s.dnsEngine)
	if err := s.dnsServer.Start(); err != nil {
		return err
	}

	log.Info("reload complete")
	return nil
}

func (s *Server) Shutdown() error {
	log.Info("shutting down subsystems")
	if s.netRules != nil {
		s.netRules.Cleanup()
	}
	if s.dnsServer != nil {
		s.dnsServer.Close()
	}
	if s.tproxy != nil {
		s.tproxy.Close()
	}
	if s.udpTpr != nil {
		s.udpTpr.Close()
	}
	if s.proxyEngine != nil {
		s.proxyEngine.Close()
	}
	if s.bpfMgr != nil {
		s.bpfMgr.Unload()
	}
	s.cancel()
	log.Info("shutdown complete")
	return nil
}

func configToUpstreams(cfg []config.DNSUpstream) []*dns.UpstreamConfig {
	var result []*dns.UpstreamConfig
	for _, u := range cfg {
		timeout := time.Duration(u.Timeout) * time.Second
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		result = append(result, &dns.UpstreamConfig{
			Type:    dns.UpstreamType(u.Type),
			Address: u.Address,
			Tag:     u.Tag,
			Timeout: timeout,
		})
	}
	return result
}

func configToRuleConfigs(configs []config.RuleConfig) []rule.RuleConfig {
	var result []rule.RuleConfig
	for _, rc := range configs {
		r := rule.RuleConfig{Tag: rc.Action.Tag, Action: rc.Action.Mode}
		switch rc.Type {
		case "domain":
			r.Domain = []string{rc.Match}
		case "domain_suffix":
			r.DomSfx = []string{rc.Match}
		case "domain_keyword":
			r.DomKw = []string{rc.Match}
		case "geoip":
			r.GeoIP = []string{rc.Match}
		case "geosite":
			r.GeoSite = []string{rc.Match}
		case "ip", "ip_cidr":
			r.IPCIDR = []string{rc.Match}
		}
		result = append(result, r)
	}
	return result
}
