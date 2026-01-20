package main

import (
	"context"
	"log"

	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gview"
)

func main() {
	cfg := loadConfig()
	// client admin still talks to server DB via existing APIs; local DB not needed
	store, err := NewStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("init db: %v", err)
	}
	if err := store.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}

	if cfg.TunnelEnabled {
		tc := &TunnelClient{cfg: cfg.Tunnel}
		_ = tc.Start(context.Background())
	}

	app := NewApp(store)
	s := ghttp.GetServer()
	s.SetPort(cfg.Port)
	view := gview.New()
	view.AddPath("template")
	s.SetView(view)
	app.RegisterRoutes(s)
	log.Printf("client admin listening on :%d", cfg.Port)
	s.Run()
}
