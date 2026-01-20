package main

import (
	"context"
	"log"

	core "webtop-user-center"
)

func main() {
	cfg := core.LoadConfig()
	store, err := core.NewStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("init db: %v", err)
	}
	if err := store.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}

	if cfg.TunnelEnabled {
		go func() {
			if err := core.StartTunnelClient(context.Background(), cfg.Tunnel); err != nil {
				log.Fatalf("start tunnel client: %v", err)
			}
		}()
	}

	app := core.NewApp(store, cfg)
	core.RunClient(cfg, app)
}
