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
	log.Info("initializing subsystems")

	// 1. Load eBPF (CIDR + stats only — no Flow Cache in Phase 2)
	log.Info("loading eBPF", map[string]interface{}{
		"interface": s.cfg.BPF.Interface,
	})
	s.bpfMgr = bpf.NewManager(s.cfg.BPF.Interface)
	result, err := s.bpfMgr.Load()
	if err != nil {
		return err
	}
	log.Info("eBPF loaded (CIDR + fwmark only)")

	// 2. Add CIDR whitelist entries
	for _, cidr := range s.cfg.BPF.CIDRWhitelist {
		if err := s.bpfMgr.AddCIDR(cidr); err != nil {
			log.Warn("add CIDR failed", map[string]interface{}{
				"cidr":  cidr,
				"error": err.Error(),
			})
		} else {
			log.Info("CIDR added", map[string]interface{}{
				"cidr": cidr,
			})
		}
	}
	_ = result // StatsMap and CidrWhitelist available via mgr

	// 3. Create Decision Cache (纯目标 key)
	s.cache = conntrack.New(1*time.Hour, 65536)
	log.Info("Decision Cache created (pure target key)")

	// 4. Start GC
	gcStop := make(chan struct{})
	s.cache.StartGC(5*time.Minute, gcStop)
	log.Info("Cache GC started (interval=5m)")

	// 5. Decision Interface
	s.decider = tproxy.NewStaticDecider()
	log.Info("Decision Interface: StaticDecider")

	// 6. Start TProxy Listener
	s.tproxy = tproxy.NewListener(
		s.cfg.TProxy.TCPAddr,
		s.decider,
		s.cache,
	)
	if err := s.tproxy.Start(); err != nil {
		return err
	}
	log.Info("TProxy listening", map[string]interface{}{
		"addr": s.cfg.TProxy.TCPAddr,
	})

	log.Info("marmot is running (Phase 2: TProxy + Decision Cache)")
	log.Info("waiting for signal")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	select {
	case sig := <-sigCh:
		log.Info("received signal", map[string]interface{}{
			"signal": sig.String(),
		})
		if sig == syscall.SIGHUP {
			log.Info("SIGHUP — config reload not yet implemented")
			return s.Shutdown()
		}
	case <-s.ctx.Done():
		log.Info("server context cancelled")
	}

	return s.Shutdown()
}

func (s *Server) Shutdown() error {
	log.Info("shutting down subsystems")

	if s.tproxy != nil {
		s.tproxy.Close()
	}
	if s.bpfMgr != nil {
		s.bpfMgr.Unload()
	}
	s.cancel()
	log.Info("shutdown complete")
	return nil
}
