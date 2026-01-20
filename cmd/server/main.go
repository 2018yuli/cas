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
		ts := &core.TunnelServer{Cfg: cfg.Tunnel}
		_ = ts.Start(context.Background())
	}

	app := core.NewApp(store)
	core.RunServer(cfg, app)
}
