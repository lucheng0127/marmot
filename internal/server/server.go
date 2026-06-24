package server

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/lucheng0127/marmot/internal/config"
	"github.com/lucheng0127/marmot/pkg/log"
)

// Server is the top-level lifecycle manager for marmot.
type Server struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc
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

	// Phase 0: only lifecycle skeleton — all subsystems are stubs
	// They will be wired in Phase 1-5.

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	log.Info("marmot is running (skeleton mode)")
	log.Info("waiting for signal")

	select {
	case sig := <-sigCh:
		log.Info("received signal", map[string]interface{}{
			"signal": sig.String(),
		})
		if sig == syscall.SIGHUP {
			// TODO: hot-reload config
			log.Info("SIGHUP received — config reload not yet implemented")
			return s.Run() // restart signal loop (simple approach for now)
		}
	case <-s.ctx.Done():
		log.Info("server context cancelled")
	}

	return s.Shutdown()
}

// Shutdown performs graceful shutdown of all subsystems.
func (s *Server) Shutdown() error {
	log.Info("shutting down subsystems")
	s.cancel()
	log.Info("shutdown complete")
	return nil
}
