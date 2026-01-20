package app

import (
	"log"

	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gview"
)

// RunServer starts the portal-only server (admin disabled for safety on server side).
func RunServer(cfg Config, app *App) {
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
	app.DisableAdmin()
	app.RegisterRoutes(s)

	log.Printf("user-center server listening on :%d", cfg.Port)
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("user-center server https on :%d", cfg.HTTPSPort)
	}

	if cfg.SyncEnabled && cfg.SyncURL != "" {
		go startWebtopSync(cfg, app.store)
	}
	s.Run()
}
