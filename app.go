package app

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	store         *Store
	cfg           Config
	adminDisabled bool
	tunnel        *TunnelServer
}

func NewApp(store *Store, cfg Config) *App {
	return &App{store: store, cfg: cfg}
}

func (a *App) DisableAdmin() {
	a.adminDisabled = true
}

func (a *App) SetTunnelServer(ts *TunnelServer) {
	a.tunnel = ts
}

func (a *App) RegisterRoutes(s *ghttp.Server) {
	s.Group("/", func(g *ghttp.RouterGroup) {
		g.Middleware(ghttp.MiddlewareCORS)
		g.GET("/", a.RenderLoginPage)
		g.GET("/portal", a.RenderPortalPage) // HTML
		g.POST("/login", a.HandleLogin)
		g.POST("/logout", a.HandleLogout)
		g.GET("/auth/check", a.HandleAuthCheck)

		g.Group("/", func(authed *ghttp.RouterGroup) {
			authed.Middleware(a.SessionMiddleware)
			authed.GET("/api/portal", a.HandlePortal)
			authed.ALL("/webtop/{id}", a.HandleWebtopProxy)
			authed.ALL("/webtop/{id}/{path:*}", a.HandleWebtopProxy)
			authed.ALL("/webtop/{id}/*path", a.HandleWebtopProxy)
			// fallback when用户直接访问 /webtop/... 不带 id，默认取用户第一个可用 webtop
			authed.ALL("/webtop/{path:*}", a.HandleWebtopDefaultProxy)

			// admin-only APIs and page
			if !a.adminDisabled {
				authed.Group("/admin", func(admin *ghttp.RouterGroup) {
					admin.Middleware(a.AdminMiddleware)
					admin.GET("/", a.RenderAdminPage)
					admin.GET("/users", a.AdminListUsers)
					admin.POST("/users", a.AdminCreateUser)
					admin.POST("/users/{id}/password", a.AdminSetUserPassword)
					admin.POST("/users/{id}/disable", a.AdminSetUserDisabled)

					admin.GET("/webtops", a.AdminListWebtops)
					admin.POST("/webtops", a.AdminCreateWebtop)
					admin.POST("/webtops/{id}", a.AdminUpdateWebtop)
					admin.DELETE("/webtops/{id}", a.AdminDeleteWebtop)
				})
			}
		})
	})
}

func (a *App) HandleLogin(r *ghttp.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := r.Parse(&req); err != nil {
		r.Response.WriteStatus(http.StatusBadRequest, "invalid json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		r.Response.WriteStatus(http.StatusBadRequest, "username/password required")
		return
	}

	user, err := a.store.GetUserByUsername(req.Username)
	if err != nil {
		r.Response.WriteStatus(http.StatusUnauthorized, "invalid credentials")
		return
	}
	now := time.Now()
	if user.Disabled {
		r.Response.WriteStatus(http.StatusForbidden, "account disabled")
		return
	}
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		r.Response.WriteStatus(http.StatusTooManyRequests, "account locked until "+user.LockedUntil.Format(time.RFC3339))
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		if lockUntil, _ := a.store.RecordFailureAndMaybeLock(user.ID); lockUntil != nil {
			r.Response.WriteStatus(http.StatusTooManyRequests, "account locked until "+lockUntil.Format(time.RFC3339))
			return
		}
		r.Response.WriteStatus(http.StatusUnauthorized, "invalid credentials")
		return
	}

	expires := now.Add(sessionTTL)
	// optional JWT for embedded Caddy
	if jwtSecret != "" {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(user.ID, 10),
			Issuer:    "webtop-user-center",
			Audience:  []string{"webtop"},
			ExpiresAt: jwt.NewNumericDate(expires),
			NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		})
		if signed, err := token.SignedString([]byte(jwtSecret)); err == nil {
			http.SetCookie(r.Response.Writer, &http.Cookie{
				Name:     jwtCookieName,
				Value:    signed,
				Path:     "/",
				Expires:  expires,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Secure:   false,
			})
		} else {
			log.Printf("sign jwt: %v", err)
		}
	}

	if err := a.store.RecordAttempt(user.ID, true); err != nil {
		log.Printf("record attempt: %v", err)
	}
	if err := a.store.ClearLock(user.ID); err != nil {
		log.Printf("clear lock: %v", err)
	}

	sessID, err := a.store.CreateSession(user.ID, expires)
	if err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(r.Response.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessID,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})
	r.Response.WriteJson(map[string]string{"status": "ok"})
}

func (a *App) HandleLogout(r *ghttp.Request) {
	if c, err := r.Request.Cookie(sessionCookieName); err == nil {
		_ = a.store.DeleteSession(c.Value)
	}
	http.SetCookie(r.Response.Writer, &http.Cookie{
		Name:     jwtCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})
	http.SetCookie(r.Response.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})
	r.Response.WriteJson(map[string]string{"status": "ok"})
}

func (a *App) HandlePortal(r *ghttp.Request) {
	userVar := r.GetCtxVar("user")
	user, ok := userVar.Interface().(User)
	if !ok {
		r.Response.WriteStatus(http.StatusUnauthorized, "unauthorized")
		return
	}
	webtops, err := a.store.ListWebtopsForUser(user.ID)
	if err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "internal error")
		return
	}
	r.Response.WriteJson(map[string]any{
		"user":    user.Username,
		"webtops": webtops,
	})
}

// ----- Admin APIs -----

func (a *App) AdminListUsers(r *ghttp.Request) {
	users, err := a.store.ListUsers()
	if err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "internal error")
		return
	}
	type userDTO struct {
		ID       int64   `json:"id"`
		Username string  `json:"username"`
		Disabled bool    `json:"disabled"`
		Locked   *string `json:"locked_until,omitempty"`
	}
	var out []userDTO
	for _, u := range users {
		var lockStr *string
		if u.LockedUntil != nil {
			s := u.LockedUntil.Format(time.RFC3339)
			lockStr = &s
		}
		out = append(out, userDTO{
			ID:       u.ID,
			Username: u.Username,
			Disabled: u.Disabled,
			Locked:   lockStr,
		})
	}
	r.Response.WriteJson(out)
}

func (a *App) AdminCreateUser(r *ghttp.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := r.Parse(&req); err != nil {
		r.Response.WriteStatus(http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Username) == "" || req.Password == "" {
		r.Response.WriteStatus(http.StatusBadRequest, "username/password required")
		return
	}
	if _, err := a.store.EnsureUserWithRole(req.Username, req.Password, []string{"user"}); err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "failed to create user")
		return
	}
	r.Response.WriteJson(map[string]string{"status": "ok"})
}

func (a *App) AdminSetUserPassword(r *ghttp.Request) {
	id, _ := strconv.ParseInt(r.Get("id").String(), 10, 64)
	var req struct {
		Password string `json:"password"`
	}
	if err := r.Parse(&req); err != nil || req.Password == "" {
		r.Response.WriteStatus(http.StatusBadRequest, "password required")
		return
	}
	if err := a.store.SetUserPassword(id, req.Password); err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "failed")
		return
	}
	r.Response.WriteJson(map[string]string{"status": "ok"})
}

func (a *App) AdminSetUserDisabled(r *ghttp.Request) {
	id, _ := strconv.ParseInt(r.Get("id").String(), 10, 64)
	var req struct {
		Disabled bool `json:"disabled"`
	}
	if err := r.Parse(&req); err != nil {
		r.Response.WriteStatus(http.StatusBadRequest, "invalid json")
		return
	}
	if err := a.store.SetUserDisabled(id, req.Disabled); err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "failed")
		return
	}
	r.Response.WriteJson(map[string]string{"status": "ok"})
}

func (a *App) AdminListWebtops(r *ghttp.Request) {
	list, err := a.store.ListWebtops()
	if err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "failed")
		return
	}
	r.Response.WriteJson(list)
}

func (a *App) AdminCreateWebtop(r *ghttp.Request) {
	var req struct {
		Name      string `json:"name"`
		TargetURL string `json:"target_url"`
		Enabled   bool   `json:"enabled"`
	}
	if err := r.Parse(&req); err != nil {
		r.Response.WriteStatus(http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.TargetURL) == "" {
		r.Response.WriteStatus(http.StatusBadRequest, "name/target_url required")
		return
	}
	if _, err := a.store.CreateWebtop(req.Name, req.TargetURL, req.Enabled); err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "failed")
		return
	}
	r.Response.WriteJson(map[string]string{"status": "ok"})
}

func (a *App) AdminUpdateWebtop(r *ghttp.Request) {
	id, _ := strconv.ParseInt(r.Get("id").String(), 10, 64)
	var req struct {
		Name      string `json:"name"`
		TargetURL string `json:"target_url"`
		Enabled   bool   `json:"enabled"`
	}
	if err := r.Parse(&req); err != nil {
		r.Response.WriteStatus(http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.TargetURL) == "" {
		r.Response.WriteStatus(http.StatusBadRequest, "name/target_url required")
		return
	}
	if err := a.store.UpdateWebtop(id, req.Name, req.TargetURL, req.Enabled); err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "failed")
		return
	}
	r.Response.WriteJson(map[string]string{"status": "ok"})
}

func (a *App) AdminDeleteWebtop(r *ghttp.Request) {
	id, _ := strconv.ParseInt(r.Get("id").String(), 10, 64)
	if id == 0 {
		r.Response.WriteStatus(http.StatusBadRequest, "bad webtop id")
		return
	}
	if err := a.store.DeleteWebtop(id); err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "failed")
		return
	}
	r.Response.WriteJson(map[string]string{"status": "ok"})
}

// When user hits /webtop/{path:*} without id, pick first accessible webtop
func (a *App) HandleWebtopDefaultProxy(r *ghttp.Request) {
	_, ok := r.GetCtxVar("user").Interface().(User)
	if !ok {
		r.Response.WriteStatus(http.StatusUnauthorized, "unauthorized")
		return
	}
	r.Response.WriteStatus(http.StatusBadRequest, "webtop id required")
}

func (a *App) serveReverseProxy(r *ghttp.Request, target *url.URL) {
	path := r.Request.URL.Path
	joinedPath := joinURLPath(target.Path, path)
	upstream := target
	if a.cfg.TunnelEnabled {
		clone := *target
		clone.Scheme = "http" // avoid TLS over tunnel; real TLS handled by client when dialing targetURL
		upstream = &clone
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	transport := &http.Transport{}
	if a.cfg.TunnelEnabled {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialTunnel(ctx, a.tunnel, a.cfg.Tunnel, target.String())
		}
		transport.DisableKeepAlives = true
	}
	// Only terminate TLS here when we are dialing the upstream directly.
	// In tunnel mode，client 会直连目标并处理 TLS。
	if target.Scheme == "https" && !a.cfg.TunnelEnabled {
		tlsCfg := &tls.Config{}
		if proxyInsecureTLS {
			tlsCfg.InsecureSkipVerify = true // intended for self-signed upstream
		} else if proxyCAFile != "" {
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			if caBytes, err := os.ReadFile(proxyCAFile); err == nil {
				pool.AppendCertsFromPEM(caBytes)
				tlsCfg.RootCAs = pool
			} else {
				log.Printf("load proxy ca file error: %v", err)
			}
		}
		transport.TLSClientConfig = tlsCfg
	}
	if transport.DialContext != nil || transport.TLSClientConfig != nil {
		proxy.Transport = transport
	}
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host
		req.URL.Path = joinedPath
		req.URL.RawPath = ""
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		ct := resp.Header.Get("Content-Type")
		if resp.StatusCode != http.StatusOK || !strings.Contains(ct, "text/html") {
			return nil
		}
		// Best-effort check; do not block to avoid false positives.
		const maxCheck = 2 * 1024 * 1024 // 2MB cap to avoid huge bodies
		reader := resp.Body
		encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
		decompressed := false
		if strings.Contains(encoding, "gzip") {
			if gz, err := gzip.NewReader(resp.Body); err == nil {
				reader = gz
				defer gz.Close()
				decompressed = true
			} else {
				log.Printf("warning: gzip decode failed, skip html check: %v", err)
				return nil
			}
		} else if strings.Contains(encoding, "deflate") {
			if fr := flate.NewReader(resp.Body); fr != nil {
				reader = fr
				defer fr.Close()
				decompressed = true
			} else {
				log.Printf("warning: deflate decode failed, skip html check")
				return nil
			}
		}
		body, err := io.ReadAll(io.LimitReader(reader, maxCheck))
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		lc := bytes.ToLower(body)
		hasApp := bytes.Contains(lc, []byte(`<div id="app"`))
		hasRoot := bytes.Contains(lc, []byte(`<div id="root"`))
		hasTouch := bytes.Contains(lc, []byte(`<div id="touch-gamepad-host"`))
		if !(hasApp && hasRoot && hasTouch) {
			resp.StatusCode = http.StatusForbidden
			resp.Status = http.StatusText(http.StatusForbidden)
			resp.Header.Del("Content-Length")
			resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
			resp.Body = io.NopCloser(strings.NewReader("forbidden: not a recognized webtop page"))
			return nil
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		if decompressed {
			resp.Header.Del("Content-Encoding")
		}
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("proxy error: %v", err)
		http.Error(rw, "upstream error", http.StatusBadGateway)
	}
	proxy.ServeHTTP(r.Response.Writer, r.Request)
}

func joinURLPath(base, suffix string) string {
	bHas := strings.HasSuffix(base, "/")
	sHas := strings.HasPrefix(suffix, "/")
	switch {
	case bHas && sHas:
		return base + strings.TrimPrefix(suffix, "/")
	case !bHas && !sHas:
		return base + "/" + suffix
	default:
		return base + suffix
	}
}
func (a *App) RenderLoginPage(r *ghttp.Request) {
	_ = r.Response.WriteTpl("login.html", nil)
}

func (a *App) RenderPortalPage(r *ghttp.Request) {
	_ = r.Response.WriteTpl("portal.html", nil)
}

func (a *App) RenderAdminPage(r *ghttp.Request) {
	_ = r.Response.WriteTpl("admin.html", nil)
}

func (a *App) HandleAuthCheck(r *ghttp.Request) {
	_, err := a.requireSession(r)
	if err != nil {
		r.Response.WriteStatus(http.StatusForbidden, "forbidden")
		return
	}
	r.Response.WriteStatus(http.StatusOK, "ok")
}

func (a *App) HandleWebtopProxy(r *ghttp.Request) {
	userVar := r.GetCtxVar("user")
	user, ok := userVar.Interface().(User)
	if !ok {
		r.Response.WriteStatus(http.StatusUnauthorized, "unauthorized")
		return
	}
	idStr := r.Get("id").String()
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		r.Response.WriteStatus(http.StatusBadRequest, "bad webtop id")
		return
	}
	webtop, err := a.store.GetWebtop(id, user.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			r.Response.WriteStatus(http.StatusNotFound)
			return
		}
		r.Response.WriteStatus(http.StatusInternalServerError, "internal error")
		return
	}
	targetURL := strings.ReplaceAll(webtop.TargetURL, "{id}", idStr)
	target, err := url.Parse(targetURL)
	if err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "invalid target")
		return
	}
	inPath := r.Request.URL.Path
	if strings.Contains(target.Path, "/webtop/") {
		r.Request.URL.Path = inPath
		r.Request.URL.RawPath = inPath
	} else {
		r.Request.URL.Path = strings.TrimPrefix(inPath, "/webtop/"+idStr)
		if r.Request.URL.Path == "" {
			r.Request.URL.Path = "/"
		}
		r.Request.URL.RawPath = r.Request.URL.Path
	}
	a.serveReverseProxy(r, target)
}

func (a *App) SessionMiddleware(r *ghttp.Request) {
	user, err := a.requireSession(r)
	if err != nil {
		r.Response.WriteStatus(http.StatusUnauthorized, "unauthorized")
		return
	}
	r.SetCtxVar("user", user)
	r.Middleware.Next()
}

func (a *App) AdminMiddleware(r *ghttp.Request) {
	userVar := r.GetCtxVar("user")
	user, ok := userVar.Interface().(User)
	if !ok {
		r.Response.WriteStatus(http.StatusUnauthorized, "unauthorized")
		return
	}
	// Allow either header secret (if configured) or admin role.
	if adminSecret != "" {
		if sec := r.Header.Get("X-Admin-Secret"); sec == adminSecret {
			r.Middleware.Next()
			return
		}
	}
	okRole, err := a.store.HasRole(user.ID, defaultAdminRole)
	if err != nil {
		r.Response.WriteStatus(http.StatusInternalServerError, "internal error")
		return
	}
	if !okRole {
		r.Response.WriteStatus(http.StatusForbidden, "forbidden")
		return
	}
	r.Middleware.Next()
}

func (a *App) requireSession(r *ghttp.Request) (User, error) {
	c, err := r.Request.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return User{}, errors.New("no session")
	}
	user, exp, err := a.store.SessionUser(c.Value)
	if err != nil {
		return User{}, err
	}
	if time.Now().After(exp) {
		_ = a.store.DeleteSession(c.Value)
		return User{}, errors.New("session expired")
	}
	if user.Disabled {
		return User{}, errors.New("disabled")
	}
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		return User{}, errors.New("locked")
	}
	return user, nil
}
