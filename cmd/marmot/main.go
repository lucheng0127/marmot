package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lucheng0127/marmot/internal/config"
	"github.com/lucheng0127/marmot/internal/server"
	"github.com/lucheng0127/marmot/pkg/log"
)

func main() {
	cfgPath := flag.String("config", "/etc/marmot/marmot.yaml", "path to config file")
	showVer := flag.Bool("version", false, "show version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println("marmot v0.1.0 — BPF transparent proxy")
		return
	}

	// Load configuration
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logging
	log.Init(
		log.FromLevel(cfg.Log.Level),
		cfg.Log.Format,
		cfg.Log.Output,
	)
	log.Info("marmot starting", map[string]interface{}{
		"config": *cfgPath,
	})

	// Create and run server
	srv := server.New(cfg)
	if err := srv.Run(); err != nil {
		log.Error("server stopped with error", map[string]interface{}{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	log.Info("marmot stopped")
}
