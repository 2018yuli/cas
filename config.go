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
	syncSecret       = ""
)

type Config struct {
	DBPath        string
	Port          int
	HTTPSPort     int
	TLSCert       string
	TLSKey        string
	AdminEnabled  bool
	AdminSecret   string
	SyncEnabled   bool
	SyncURL       string
	SyncSecret    string
	SyncInterval  time.Duration
	TunnelEnabled bool
	Tunnel        TunnelConfig
	TOMLPath      string
}

type AdminSection struct {
	Enabled bool   `toml:"enabled"`
	Secret  string `toml:"secret"`
}

type SyncSection struct {
	Enabled  bool   `toml:"enabled"`
	URL      string `toml:"url"`
	Secret   string `toml:"secret"`
	Interval int    `toml:"interval_sec"` // seconds
}

type TunnelSection struct {
	Enabled      bool   `toml:"enabled"`
	ServerAddr   string `toml:"server_addr"`
	ControlPort  int    `toml:"control_port"`
	DataPort     int    `toml:"data_port"`
	PublicPort   int    `toml:"public_port"`
	LocalTarget  string `toml:"local_target"`
	Secret       string `toml:"secret"`
	ReconnectSec int    `toml:"reconnect_sec"`
}

func (t TunnelSection) ToConfig() TunnelConfig {
	cfg := loadTunnelConfig()
	if t.ServerAddr != "" {
		cfg.ServerAddr = t.ServerAddr
	}
	if t.ControlPort > 0 {
		cfg.ControlPort = t.ControlPort
	}
	if t.DataPort > 0 {
		cfg.DataPort = t.DataPort
	}
	if t.PublicPort > 0 {
		cfg.PublicPort = t.PublicPort
	}
	if t.LocalTarget != "" {
		cfg.LocalTarget = t.LocalTarget
	}
	if t.Secret != "" {
		cfg.Secret = t.Secret
	}
	if t.ReconnectSec > 0 {
		cfg.ReconnectSec = t.ReconnectSec
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
			Sync      SyncSection   `toml:"sync"`
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
				adminSecret = cfg.AdminSecret
			}
			cfg.SyncEnabled = fileCfg.Sync.Enabled
			if fileCfg.Sync.URL != "" {
				cfg.SyncURL = fileCfg.Sync.URL
			}
			if fileCfg.Sync.Secret != "" {
				cfg.SyncSecret = fileCfg.Sync.Secret
				syncSecret = cfg.SyncSecret
			}
			if fileCfg.Sync.Interval > 0 {
				cfg.SyncInterval = time.Duration(fileCfg.Sync.Interval) * time.Second
			}
			cfg.TunnelEnabled = fileCfg.Tunnel.Enabled
			cfg.Tunnel = fileCfg.Tunnel.ToConfig()
		} else {
			log.Printf("failed to parse %s: %v", cfg.TOMLPath, err)
		}
	}
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
	syncSecret = strings.TrimSpace(os.Getenv("SYNC_SECRET"))

	syncEnabled := false
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("SYNC_ENABLED"))); v == "1" || v == "true" || v == "yes" {
		syncEnabled = true
	}
	syncURL := strings.TrimSpace(os.Getenv("SYNC_URL"))
	syncInterval := envInt("SYNC_INTERVAL_SEC", 300)

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
		SyncEnabled:   syncEnabled,
		SyncURL:       syncURL,
		SyncSecret:    syncSecret,
		SyncInterval:  time.Duration(syncInterval) * time.Second,
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
