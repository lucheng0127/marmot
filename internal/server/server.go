package server

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lucheng0127/marmot/internal/config"
	"github.com/lucheng0127/marmot/pkg/bpf"
	"github.com/lucheng0127/marmot/pkg/conntrack"
	"github.com/lucheng0127/marmot/pkg/dns"
	"github.com/lucheng0127/marmot/pkg/log"
	"github.com/lucheng0127/marmot/pkg/proxy"
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

	proxyEngine *proxy.Engine
	nodeMgr     *proxy.NodeManager
	healthChk   *proxy.HealthChecker
	optsConv    *proxy.OptionsConverter

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
	log.Info("initializing Phase 4 subsystems")

	// 1. eBPF
	s.bpfMgr = bpf.NewManager(s.cfg.BPF.Interface)
	result, err := s.bpfMgr.Load()
	if err != nil {
		return err
	}
	for _, cidr := range s.cfg.BPF.CIDRWhitelist {
		_ = s.bpfMgr.AddCIDR(cidr)
	}
	_ = result

	// 2. Decision Cache
	s.cache = conntrack.New(1*time.Hour, 65536)
	s.cache.StartGC(5*time.Minute, make(chan struct{}))

	// 3. Decision Interface
	s.decider = tproxy.NewStaticDecider()

	// 4. Node Manager
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

	// 6. TCP TProxy
	relayAddr := s.cfg.TProxy.OutboundAddr
	if relayAddr == "" {
		relayAddr = "127.0.0.1:10800"
	}
	s.tproxy = tproxy.NewListener(s.cfg.TProxy.TCPAddr, s.decider, s.cache, relayAddr)
	if err := s.tproxy.Start(); err != nil {
		return err
	}

	// 7. UDP TProxy
	s.udpTpr = tproxy.NewUDPListener(s.cfg.TProxy.UDPAddr, s.decider, s.cache, relayAddr)
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

	// 11. DNS Engine
	s.dnsEngine = dns.NewEngine(upstreams, s.dnsCache)

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

	log.Info("marmot is running (Phase 4: DNS + TProxy + sing-box outbound)")
	log.Info("waiting for signal")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	select {
	case sig := <-sigCh:
		log.Info("received signal", map[string]interface{}{"signal": sig.String()})
	case <-s.ctx.Done():
	}
	return s.Shutdown()
}

func (s *Server) Shutdown() error {
	log.Info("shutting down subsystems")
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
