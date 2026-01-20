package app

import (
	"log"

	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gview"
)

// RunClient starts the admin-enabled UI (intended for client side).
func RunClient(cfg Config, app *App) {
	s := ghttp.GetServer()
	s.SetPort(cfg.Port)
	view := gview.New()
	view.AddPath("template")
	s.SetView(view)
	app.RegisterRoutes(s)
	log.Printf("client admin listening on :%d", cfg.Port)
	s.Run()
}
