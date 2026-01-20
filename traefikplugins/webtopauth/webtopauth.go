// Package webtopauth implements a Traefik middleware plugin that delegates
// authentication to an external endpoint (e.g., the Go 用户中心的 `/auth/check`).
// It mimics ForwardAuth but is self-contained for scenarios that prefer a plugin.
package webtopauth

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Config holds plugin configuration.
type Config struct {
	// AuthURL is the endpoint to call for auth check (expects 2xx to allow).
	AuthURL string `json:"authURL,omitempty"`
	// Timeout for the auth request.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// CreateConfig sets default config.
func CreateConfig() *Config {
	return &Config{
		Timeout: 5 * time.Second,
	}
}

// WebtopAuth middleware.
type WebtopAuth struct {
	next    http.Handler
	name    string
	authURL string
	client  *http.Client
}

// New creates a new middleware.
func New(_ context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	return &WebtopAuth{
		next:    next,
		name:    name,
		authURL: cfg.AuthURL,
		client: &http.Client{
			Transport: tr,
			Timeout:   timeout,
		},
	}, nil
}

// ServeHTTP checks auth via AuthURL; on 2xx proceeds, otherwise relays status/body.
func (w *WebtopAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if w.authURL == "" {
		http.Error(rw, "authURL not configured", http.StatusInternalServerError)
		return
	}

	authReq, err := http.NewRequest(http.MethodGet, w.authURL, nil)
	if err != nil {
		http.Error(rw, "auth request build error", http.StatusInternalServerError)
		return
	}

	// Forward cookies and relevant headers for context.
	for _, c := range req.Cookies() {
		authReq.AddCookie(c)
	}
	authReq.Header.Set("X-Original-Method", req.Method)
	authReq.Header.Set("X-Original-Uri", req.URL.RequestURI())
	authReq.Header.Set("X-Original-Host", req.Host)

	xfw := req.Header.Get("X-Forwarded-For")
	if xfw == "" {
		xfw = clientIP(req)
	} else if ip := clientIP(req); ip != "" {
		xfw = xfw + ", " + ip
	}
	if xfw != "" {
		authReq.Header.Set("X-Forwarded-For", xfw)
	}
	if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" {
		authReq.Header.Set("X-Forwarded-Proto", proto)
	}
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		authReq.Header.Set("X-Forwarded-Host", host)
	}

	resp, err := w.client.Do(authReq)
	if err != nil {
		http.Error(rw, "auth upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		w.next.ServeHTTP(rw, req)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	for k, vals := range resp.Header {
		for _, v := range vals {
			rw.Header().Add(k, v)
		}
	}
	rw.WriteHeader(resp.StatusCode)
	rw.Write(body)
}

func clientIP(r *http.Request) string {
	hostPort := r.RemoteAddr
	if hostPort == "" {
		return ""
	}
	if strings.Contains(hostPort, ":") {
		if host, _, err := net.SplitHostPort(hostPort); err == nil {
			return host
		}
	}
	return hostPort
}
