package main

import (
	"context"
	"log"
	"time"

	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gview"
)

func main() {
	cfg := loadConfig()
	store, err := NewStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("init db: %v", err)
	}
	if err := store.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}
	if jwtSecret == "" {
		log.Printf("warning: JWT_SECRET not set, embedded Caddy gateway will be disabled")
	}

	if cfg.TunnelEnabled {
		ts := &TunnelServer{cfg: cfg.Tunnel}
		_ = ts.Start(context.Background())
	}

	app := NewApp(store)
	s := ghttp.GetServer()
	s.SetPort(cfg.Port)
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		s.EnableHTTPS(cfg.TLSCert, cfg.TLSKey)
		s.SetHTTPSPort(cfg.HTTPSPort)
		log.Printf("https enabled on :%d", cfg.HTTPSPort)
	}
	view := gview.New()
	view.AddPath("template")
	s.SetView(view)
	app.RegisterRoutes(s)

	// server runs without admin UI for safety
	app.DisableAdmin()

	log.Printf("user-center server listening on :%d", cfg.Port)
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("user-center server https on :%d", cfg.HTTPSPort)
	}

	s.Run()
	time.Sleep(100 * time.Millisecond)
}
