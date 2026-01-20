package app

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
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
	TOMLPath      string
}

type AdminSection struct {
	Enabled bool   `toml:"enabled"`
	Secret  string `toml:"secret"`
}

type TunnelSection struct {
	Enabled     bool   `toml:"enabled"`
	ServerAddr  string `toml:"server_addr"`
	DataPort    int    `toml:"data_port"`
	Secret      string `toml:"secret"`
	TLSEnabled  bool   `toml:"tls_enabled"`
	TLSCert     string `toml:"tls_cert"`
	TLSKey      string `toml:"tls_key"`
	TLSInsecure bool   `toml:"tls_insecure"`
	ConnCount   int    `toml:"conn_count"`
}

func (t TunnelSection) ToConfig() TunnelConfig {
	cfg := loadTunnelConfig()
	if t.ServerAddr != "" {
		cfg.ServerAddr = t.ServerAddr
	}
	if t.DataPort > 0 {
		cfg.DataPort = t.DataPort
	}
	if t.Secret != "" {
		cfg.Secret = t.Secret
	}
	if t.TLSEnabled {
		cfg.TLSEnabled = true
	}
	if t.TLSCert != "" {
		cfg.TLSCert = t.TLSCert
	}
	if t.TLSKey != "" {
		cfg.TLSKey = t.TLSKey
	}
	if t.TLSInsecure {
		cfg.TLSInsecure = true
	}
	if t.ConnCount > 0 {
		cfg.ConnCount = t.ConnCount
	}
	return cfg
}

func LoadConfig() Config {
	cfg := loadFromEnv()

	// override from config.toml if present
	cfg.TOMLPath = strings.TrimSpace(os.Getenv("CONFIG_FILE"))
	if cfg.TOMLPath == "" {
		cfg.TOMLPath = "config.toml"
	}
	if stat, err := os.Stat(cfg.TOMLPath); err == nil && !stat.IsDir() {
		var fileCfg struct {
			DBPath    string        `toml:"db_path"`
			Port      int           `toml:"port"`
			HTTPSPort int           `toml:"https_port"`
			TLSCert   string        `toml:"tls_cert"`
			TLSKey    string        `toml:"tls_key"`
			Admin     AdminSection  `toml:"admin"`
			Tunnel    TunnelSection `toml:"tunnel"`
		}
		if _, err := toml.DecodeFile(cfg.TOMLPath, &fileCfg); err == nil {
			if fileCfg.DBPath != "" {
				cfg.DBPath = fileCfg.DBPath
			}
			if fileCfg.Port > 0 {
				cfg.Port = fileCfg.Port
			}
			if fileCfg.HTTPSPort > 0 {
				cfg.HTTPSPort = fileCfg.HTTPSPort
			}
			if fileCfg.TLSCert != "" && fileCfg.TLSKey != "" {
				cfg.TLSCert = fileCfg.TLSCert
				cfg.TLSKey = fileCfg.TLSKey
			}
			cfg.AdminEnabled = fileCfg.Admin.Enabled
			if fileCfg.Admin.Secret != "" {
				cfg.AdminSecret = fileCfg.Admin.Secret
			}
			cfg.TunnelEnabled = fileCfg.Tunnel.Enabled
			cfg.Tunnel = fileCfg.Tunnel.ToConfig()
		} else {
			log.Printf("failed to parse %s: %v", cfg.TOMLPath, err)
		}
	}
	adminSecret = cfg.AdminSecret
	return cfg
}

func loadFromEnv() Config {
	dbPath := strings.TrimSpace(os.Getenv("DB_PATH"))
	if dbPath == "" {
		dbPath = defaultDBPath
	}
	port := envInt("PORT", 8080)
	httpsPort := envInt("HTTPS_PORT", 8443)
	tlsCert := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	tlsKey := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	adminEnabled := true
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_ENABLED"))); v == "0" || v == "false" || v == "no" {
		adminEnabled = false
	}
	adminSecret = strings.TrimSpace(os.Getenv("ADMIN_SECRET"))

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

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
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
