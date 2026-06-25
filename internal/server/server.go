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
	"github.com/lucheng0127/marmot/pkg/log"
	"github.com/lucheng0127/marmot/pkg/proxy"
	"github.com/lucheng0127/marmot/pkg/tproxy"
)

// Server is the top-level lifecycle manager for marmot.
type Server struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc

	bpfMgr  *bpf.Manager
	tproxy  *tproxy.Listener
	decider tproxy.Decider
	cache   *conntrack.Cache

	// Phase 3 subsystems
	proxyEngine *proxy.Engine
	nodeMgr     *proxy.NodeManager
	healthChk   *proxy.HealthChecker
	optsConv    *proxy.OptionsConverter
}

func New(cfg *config.Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *Server) Run() error {
	log.Info("initializing Phase 3 subsystems")

	// ── 1. eBPF ──
	s.bpfMgr = bpf.NewManager(s.cfg.BPF.Interface)
	result, err := s.bpfMgr.Load()
	if err != nil {
		return err
	}
	for _, cidr := range s.cfg.BPF.CIDRWhitelist {
		_ = s.bpfMgr.AddCIDR(cidr)
	}
	_ = result

	// ── 2. Decision Cache ──
	s.cache = conntrack.New(1*time.Hour, 65536)
	gcStop := make(chan struct{})
	s.cache.StartGC(5*time.Minute, gcStop)
	_ = gcStop

	// ── 3. Decision Interface ──
	s.decider = tproxy.NewStaticDecider()

	// ── 4. TProxy ──
	s.tproxy = tproxy.NewListener(s.cfg.TProxy.TCPAddr, s.decider, s.cache)
	if err := s.tproxy.Start(); err != nil {
		return err
	}

	// ── 5. Node Manager ──
	s.nodeMgr = proxy.NewNodeManager()
	for tag, nodeCfg := range s.cfg.Proxy.Nodes {
		s.nodeMgr.AddNode(tag, nodeCfg)
	}

	// ── 6. Options Converter + Engine ──
	s.optsConv = proxy.NewOptionsConverter()
	options := s.optsConv.ToOptions(s.nodeMgr)
	s.proxyEngine, err = proxy.New(s.ctx, options)
	if err != nil {
		return err
	}
	if err := s.proxyEngine.Start(); err != nil {
		return err
	}
	log.Info("sing-box engine started", map[string]interface{}{
		"nodes": s.nodeMgr.Count(),
	})

	// ── 7. Health Checker ──
	s.healthChk = proxy.NewHealthChecker(s.nodeMgr, 30*time.Second, 5*time.Second)
	s.healthChk.Start(s.ctx)

	log.Info("marmot is running (Phase 3: TProxy + sing-box outbound)")
	log.Info("waiting for signal")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	select {
	case sig := <-sigCh:
		log.Info("received signal", map[string]interface{}{"signal": sig.String()})
		if sig == syscall.SIGHUP {
			log.Info("SIGHUP — config reload not yet implemented")
			return s.Shutdown()
		}
	case <-s.ctx.Done():
	}

	return s.Shutdown()
}

func (s *Server) Shutdown() error {
	log.Info("shutting down subsystems")

	if s.tproxy != nil {
		s.tproxy.Close()
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
