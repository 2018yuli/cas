package app

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
)

// JWTGuard is a lightweight Caddy middleware to validate JWTs (HS256).
type JWTGuard struct {
	Secret     string   `json:"secret,omitempty"`
	CookieName string   `json:"cookie_name,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	Issuer     string   `json:"iss,omitempty"`
}

// CaddyModule registers the module.
func (JWTGuard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jwt_guard",
		New: func() caddy.Module { return new(JWTGuard) },
	}
}

// Provision sets defaults.
func (j *JWTGuard) Provision(_ caddy.Context) error {
	if j.CookieName == "" {
		j.CookieName = "uc_jwt"
	}
	if j.Secret == "" {
		j.Secret = os.Getenv("JWT_SECRET")
	}
	return nil
}

// Validate simple config validation.
func (j *JWTGuard) Validate() error {
	if j.Secret == "" {
		return fmt.Errorf("jwt_guard: secret is empty")
	}
	return nil
}

// ServeHTTP enforces JWT before calling next.
func (j *JWTGuard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	tokenStr := ""
	if c, err := r.Cookie(j.CookieName); err == nil {
		tokenStr = c.Value
	}
	if tokenStr == "" {
		ah := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(ah), "bearer ") {
			tokenStr = strings.TrimSpace(ah[7:])
		}
	}
	if tokenStr == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return nil
	}

	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return []byte(j.Secret), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return nil
	}

	now := time.Now()
	if claims.NotBefore != nil && claims.NotBefore.Time.After(now) {
		http.Error(w, "token not valid yet", http.StatusUnauthorized)
		return nil
	}
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(now) {
		http.Error(w, "token expired", http.StatusUnauthorized)
		return nil
	}
	if j.Issuer != "" && claims.Issuer != j.Issuer {
		http.Error(w, "issuer mismatch", http.StatusUnauthorized)
		return nil
	}
	if len(j.Audience) > 0 {
		ok := false
		for _, a := range claims.Audience {
			if a == j.Audience[0] {
				ok = true
				break
			}
		}
		if !ok {
			http.Error(w, "audience mismatch", http.StatusUnauthorized)
			return nil
		}
	}

	return next.ServeHTTP(w, r)
}

func init() {
	caddy.RegisterModule(JWTGuard{})
}

// Interface guards.
var (
	_ caddyhttp.MiddlewareHandler = (*JWTGuard)(nil)
	_ caddy.Provisioner           = (*JWTGuard)(nil)
	_ caddy.Validator             = (*JWTGuard)(nil)
)
