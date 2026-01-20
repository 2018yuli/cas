package main

import (
	"encoding/json"
	"log"
	"strconv"

	"github.com/caddyserver/caddy/v2"
)

// startCaddyGateway spins up an embedded Caddy instance listening on port+1 (default 9090)
// with jwt_guard + reverse_proxy to the main GoFrame server.
func startCaddyGateway(appPort int) error {
	if jwtSecret == "" {
		log.Printf("skip caddy gateway: JWT_SECRET not set")
		return nil
	}
	gatewayPort := appPort + 1
	cfg := map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"gateway": map[string]any{
						"listen": []string{":" + strconv.Itoa(gatewayPort)},
						"routes": []any{
							map[string]any{
								"match": []any{map[string]any{"path": []string{"/*"}}},
								"handle": []any{
									map[string]any{
										"handler":     "jwt_guard",
										"secret":      jwtSecret,
										"cookie_name": jwtCookieName,
										"aud":         []string{"webtop"},
										"iss":         "webtop-user-center",
									},
									map[string]any{
										"handler": "reverse_proxy",
										"upstreams": []any{
											map[string]any{"dial": "127.0.0.1:" + strconv.Itoa(appPort)},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	log.Printf("starting embedded caddy gateway on :%d", gatewayPort)
	return caddy.Load(data, true)
}
