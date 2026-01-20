package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	tunnelMagic    = "TUNL"
	maxTunnelField = 4096
)

type TunnelConfig struct {
	ServerAddr  string
	DataPort    int
	Secret      string
	TLSEnabled  bool
	TLSCert     string
	TLSKey      string
	TLSInsecure bool
	ConnCount   int
}

func loadTunnelConfig() TunnelConfig {
	return TunnelConfig{
		ServerAddr:  envOr("TUNNEL_SERVER_ADDR", "127.0.0.1"),
		DataPort:    envInt("TUNNEL_DATA_PORT", 9101),
		Secret:      envOr("TUNNEL_SECRET", "change-me-tunnel-secret"),
		TLSEnabled:  strings.EqualFold(envOr("TUNNEL_TLS_ENABLED", "false"), "true"),
		TLSCert:     envOr("TUNNEL_TLS_CERT", ""),
		TLSKey:      envOr("TUNNEL_TLS_KEY", ""),
		TLSInsecure: strings.EqualFold(envOr("TUNNEL_TLS_INSECURE", "false"), "true"),
		ConnCount:   envInt("TUNNEL_CONN_COUNT", 4),
	}
}

// TunnelServer accepts inbound tunnel connections (from client) and hands them out per request.
type TunnelServer struct {
	cfg    TunnelConfig
	ln     net.Listener
	connCh chan net.Conn
}

// StartTunnelServer listens on cfg.ServerAddr:cfg.DataPort and verifies secrets.
func StartTunnelServer(ctx context.Context, cfg TunnelConfig) (*TunnelServer, error) {
	addr := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.DataPort)
	var ln net.Listener
	var err error
	if cfg.TLSEnabled {
		if cfg.TLSCert == "" || cfg.TLSKey == "" {
			return nil, errors.New("tunnel tls enabled but cert/key not provided")
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load tunnel cert: %w", err)
		}
		ln, err = tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	ts := &TunnelServer{
		cfg:    cfg,
		ln:     ln,
		connCh: make(chan net.Conn, 32),
	}
	go ts.acceptLoop(ctx)
	return ts, nil
}

func (t *TunnelServer) acceptLoop(ctx context.Context) {
	log.Printf("tunnel server listening on %s", t.ln.Addr().String())
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("tunnel accept error: %v", err)
			continue
		}
		go func(c net.Conn) {
			if err := verifyMagicAndSecret(c, t.cfg.Secret); err != nil {
				log.Printf("tunnel auth error: %v", err)
				c.Close()
				return
			}
			select {
			case t.connCh <- c:
			default:
				log.Printf("tunnel backlog full, closing connection")
				c.Close()
			}
		}(conn)
	}
}

// GetConn blocks until a client-provided tunnel connection is available or ctx is done.
func (t *TunnelServer) GetConn(ctx context.Context) (net.Conn, error) {
	select {
	case c := <-t.connCh:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		return nil, errors.New("no tunnel connection available")
	}
}

// Client side: dial server, authenticate, wait for target instruction, then proxy.
func StartTunnelClient(ctx context.Context, cfg TunnelConfig) error {
	serverAddr := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.DataPort)
	workers := cfg.ConnCount
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				var conn net.Conn
				var err error
				if cfg.TLSEnabled {
					tlsCfg := &tls.Config{InsecureSkipVerify: cfg.TLSInsecure}
					conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", serverAddr, tlsCfg)
				} else {
					dialer := net.Dialer{Timeout: 5 * time.Second}
					conn, err = dialer.DialContext(ctx, "tcp", serverAddr)
				}
				if err != nil {
					log.Printf("tunnel connect error: %v", err)
					time.Sleep(2 * time.Second)
					continue
				}
				if err := writeMagicAndSecret(conn, cfg.Secret); err != nil {
					log.Printf("tunnel auth send error: %v", err)
					conn.Close()
					time.Sleep(2 * time.Second)
					continue
				}
				handleTunnelConn(conn, cfg)
			}
		}()
	}
	<-ctx.Done()
	return nil
}

// Server side dialer when a TunnelServer is available; falls back to direct dial if ts is nil.
func DialTunnel(ctx context.Context, ts *TunnelServer, cfg TunnelConfig, targetURL string) (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if ts != nil {
			conn, err := ts.GetConn(ctx)
			if err != nil {
				return nil, err
			}
			if err := writeString(conn, targetURL); err != nil {
				log.Printf("tunnel write target error: %v", err)
				conn.Close()
				continue
			}
			return conn, nil
		}
		// fallback: direct dial (non-NAT)
		addr := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.DataPort)
		var conn net.Conn
		var err error
		if cfg.TLSEnabled {
			tlsCfg := &tls.Config{InsecureSkipVerify: cfg.TLSInsecure}
			conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tlsCfg)
		} else {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			conn, err = dialer.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, err
		}
		if err := writeMagicAndSecret(conn, cfg.Secret); err != nil {
			conn.Close()
			return nil, err
		}
		if err := writeString(conn, targetURL); err != nil {
			log.Printf("tunnel write target error: %v", err)
			conn.Close()
			continue
		}
		return conn, nil
	}
	return nil, errors.New("no tunnel connection available")
}

func handleTunnelConn(c net.Conn, cfg TunnelConfig) {
	defer c.Close()
	targetURL, err := readString(c)
	if err != nil {
		log.Printf("tunnel read target error: %v", err)
		return
	}
	log.Printf("tunnel recv target=%s from %s", targetURL, c.RemoteAddr())
	u, err := url.Parse(targetURL)
	if err != nil {
		log.Printf("tunnel parse target error: %v", err)
		return
	}
	targetConn, err := dialTarget(u)
	if err != nil {
		log.Printf("tunnel dial target error: %v", err)
		return
	}
	log.Printf("tunnel connected target=%s", u.String())
	defer targetConn.Close()
	pipeConn(c, targetConn)
}

func writeMagicAndSecret(w io.Writer, secret string) error {
	if _, err := w.Write([]byte(tunnelMagic)); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(secret))
	_, err := w.Write(sum[:])
	return err
}

func verifyMagicAndSecret(r io.Reader, secret string) error {
	magic := make([]byte, len(tunnelMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return err
	}
	if string(magic) != tunnelMagic {
		return errors.New("bad magic")
	}
	var recv [32]byte
	if _, err := io.ReadFull(r, recv[:]); err != nil {
		return err
	}
	if sha256.Sum256([]byte(secret)) != recv {
		return errors.New("bad secret")
	}
	return nil
}

func writeString(w io.Writer, s string) error {
	if len(s) > maxTunnelField {
		return fmt.Errorf("field too long")
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(s)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write([]byte(s))
	return err
}

func readString(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n > maxTunnelField {
		return "", errors.New("field too long")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func dialTarget(u *url.URL) (net.Conn, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	if u.Scheme == "https" {
		return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	}
	return net.DialTimeout("tcp", host, 5*time.Second)
}

func pipeConn(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}
