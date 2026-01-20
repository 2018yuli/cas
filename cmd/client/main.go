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
		tc := &core.TunnelClient{Cfg: cfg.Tunnel}
		_ = tc.Start(context.Background())
	}

	app := core.NewApp(store)
	core.RunClient(cfg, app)
}
