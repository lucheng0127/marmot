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

	// Phase 2 subsystems
	bpfMgr   *bpf.Manager
	tproxy   *tproxy.Listener
	ctCache  *conntrack.Cache
	ctSync   *conntrack.SyncManager
}

// New creates a new Server with the given config.
func New(cfg *config.Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Run starts all subsystems and blocks until a signal or error.
func (s *Server) Run() error {
	log.Info("initializing subsystems")

	// ── Phase 2 subsystems ──

	// 1. Load eBPF (TC ingress + Flow Map + CIDR + Stats)
	log.Info("loading eBPF", map[string]interface{}{
		"interface": s.cfg.BPF.Interface,
	})
	s.bpfMgr = bpf.NewManager(s.cfg.BPF.Interface)
	result, err := s.bpfMgr.Load()
	if err != nil {
		return err
	}
	log.Info("eBPF loaded successfully")

	// 2. Add CIDR whitelist entries from config
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

	// 3. Create Conntrack Cache
	s.ctCache = conntrack.New(1*time.Hour, 65536)
	log.Info("Conntrack Cache created")

	// 4. Create SyncManager and connect to BPF Flow Maps (hybrid key)
	s.ctSync = conntrack.NewSyncManager(result.TcpFlowMap, result.UdpFlowMap, s.ctCache)
	s.ctSync.Connect()
	log.Info("BPF Flow Map sync connected (TCP: 4-tuple, UDP: 5-tuple)")

	// 5. Start Conntrack GC
	gcStop := make(chan struct{})
	s.ctCache.StartGC(5*time.Minute, gcStop)
	log.Info("Conntrack GC started (interval=5m)")

	// 6. Create Decision Interface
	decider := tproxy.NewStaticDecider()
	log.Info("Decision Interface: StaticDecider (all traffic → proxy)")

	// 7. Start TProxy Listener
	s.tproxy = tproxy.NewListener(
		s.cfg.TProxy.TCPAddr,
		decider,
		s.ctCache,
	)
	if err := s.tproxy.Start(); err != nil {
		return err
	}

	log.Info("marmot is running (Phase 2: TProxy + Conntrack)")
	log.Info("waiting for signal")

	// ── Signal handling ──
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	select {
	case sig := <-sigCh:
		log.Info("received signal", map[string]interface{}{
			"signal": sig.String(),
		})
		if sig == syscall.SIGHUP {
			log.Info("SIGHUP — config reload not yet implemented")
			return s.shutdownAndRestart()
		}
	case <-s.ctx.Done():
		log.Info("server context cancelled")
	}

	return s.Shutdown()
}

// Shutdown performs graceful shutdown of all subsystems.
func (s *Server) Shutdown() error {
	log.Info("shutting down subsystems")

	if s.tproxy != nil {
		if err := s.tproxy.Close(); err != nil {
			log.Error("TProxy close error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	if s.bpfMgr != nil {
		if err := s.bpfMgr.Unload(); err != nil {
			log.Error("BPF unload error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	s.cancel()
	log.Info("shutdown complete")
	return nil
}

func (s *Server) shutdownAndRestart() error {
	s.Shutdown()
	return s.Run()
}
