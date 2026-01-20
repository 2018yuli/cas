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

	var ts *core.TunnelServer
	if cfg.TunnelEnabled {
		var err error
		ts, err = core.StartTunnelServer(context.Background(), cfg.Tunnel)
		if err != nil {
			log.Fatalf("start tunnel server: %v", err)
		}
	}

	app := core.NewApp(store, cfg)
	app.SetTunnelServer(ts)
	core.RunServer(cfg, app)
}
