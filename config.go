package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultDBPath        = "data/user-center.db"
	sessionCookieName    = "uc_session"
	jwtCookieName        = "uc_jwt"
	baseLockDuration     = 5 * time.Minute
	maxLockDuration      = 365 * 24 * time.Hour
	defaultAdminUser     = "admin"
	defaultAdminPassword = "admin123"
	defaultAdminRole     = "admin"
)

var (
	sessionTTL       = 8 * time.Hour
	bcryptCost       = bcrypt.DefaultCost
	jwtSecret        = ""
	proxyInsecureTLS = true // 默认关闭上游 TLS 校验，便于自签 Webtop
	proxyCAFile      = ""
	adminSecret      = ""
)

type Config struct {
	DBPath        string
	Port          int
	HTTPSPort     int
	TLSCert       string
	TLSKey        string
	AdminEnabled  bool
	AdminSecret   string
	TunnelEnabled bool
	Tunnel        TunnelConfig
}

func loadConfig() Config {
	dbPath := strings.TrimSpace(os.Getenv("DB_PATH"))
	if dbPath == "" {
		dbPath = defaultDBPath
	}
	port := 8080
	if v := strings.TrimSpace(os.Getenv("PORT")); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			port = p
		}
	}
	httpsPort := 8443
	if v := strings.TrimSpace(os.Getenv("HTTPS_PORT")); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			httpsPort = p
		}
	}
	tlsCert := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	tlsKey := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	adminEnabled := true
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_ENABLED"))); v == "0" || v == "false" || v == "no" {
		adminEnabled = false
	}
	adminSecret = strings.TrimSpace(os.Getenv("ADMIN_SECRET"))
	if adminSecret == "" {
		adminSecret = defaultAdminSecret()
	}

	tunnelEnabled := false
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("TUNNEL_ENABLED"))); v == "1" || v == "true" || v == "yes" {
		tunnelEnabled = true
	}
	return Config{
		DBPath:        dbPath,
		Port:          port,
		HTTPSPort:     httpsPort,
		TLSCert:       tlsCert,
		TLSKey:        tlsKey,
		AdminEnabled:  adminEnabled,
		AdminSecret:   adminSecret,
		TunnelEnabled: tunnelEnabled,
		Tunnel:        loadTunnelConfig(),
	}
}

func init() {
	if v := strings.TrimSpace(os.Getenv("SESSION_TTL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			sessionTTL = d
			log.Printf("session ttl override: %s", d)
		}
	}
	if v := os.Getenv("BCRYPT_COST"); v != "" {
		if cost, err := strconv.Atoi(v); err == nil && cost >= bcrypt.MinCost && cost <= bcrypt.MaxCost {
			bcryptCost = cost
			log.Printf("bcrypt cost override: %d", bcryptCost)
		}
	}
	if v := strings.TrimSpace(os.Getenv("JWT_SECRET")); v != "" {
		jwtSecret = v
		log.Printf("jwt secret configured")
	}
	if v := strings.TrimSpace(os.Getenv("PROXY_INSECURE")); v != "" {
		vLower := strings.ToLower(v)
		if vLower == "0" || vLower == "false" || vLower == "no" {
			proxyInsecureTLS = false
			log.Printf("proxy tls verify enabled (PROXY_INSECURE=%s)", vLower)
		} else {
			proxyInsecureTLS = true
			log.Printf("proxy tls verify disabled (PROXY_INSECURE=%s)", vLower)
		}
	} else {
		log.Printf("proxy tls verify disabled by default (PROXY_INSECURE default true)")
	}
	if v := strings.TrimSpace(os.Getenv("PROXY_CA_FILE")); v != "" {
		proxyCAFile = v
		log.Printf("proxy custom CA: %s", proxyCAFile)
	}
}

func defaultAdminSecret() string {
	return "admin-secret-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}
