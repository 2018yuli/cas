package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TunnelConfig struct {
	ServerAddr   string // server host:port (control + data share host)
	ControlPort  int    // control channel port
	DataPort     int    // data channel port
	PublicPort   int    // server listening port to expose
	LocalTarget  string // client local target (ip:port)
	Secret       string // pre-shared secret
	ReconnectSec int
}

func loadTunnelConfig() TunnelConfig {
	return TunnelConfig{
		ServerAddr:   envOr("TUNNEL_SERVER_ADDR", "127.0.0.1"),
		ControlPort:  envInt("TUNNEL_CTRL_PORT", 9100),
		DataPort:     envInt("TUNNEL_DATA_PORT", 9101),
		PublicPort:   envInt("TUNNEL_PUBLIC_PORT", 10080),
		LocalTarget:  envOr("TUNNEL_LOCAL_TARGET", "127.0.0.1:8080"),
		Secret:       envOr("TUNNEL_SECRET", "changeme"),
		ReconnectSec: envInt("TUNNEL_RECONNECT_SEC", 5),
	}
}

// ================= Tunnel Server =================

type TunnelServer struct {
	Cfg      TunnelConfig
	ctrlConn net.Conn
	mu       sync.Mutex
}

func (ts *TunnelServer) Start(ctx context.Context) error {
	go ts.listenControl(ctx)
	go ts.listenData(ctx) // noop but keep port reserved
	go ts.listenPublic(ctx)
	return nil
}

func (ts *TunnelServer) listenControl(ctx context.Context) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", ts.Cfg.ControlPort))
	if err != nil {
		log.Printf("tunnel control listen error: %v", err)
		return
	}
	log.Printf("tunnel control listening on :%d", ts.Cfg.ControlPort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("control accept error: %v", err)
			continue
		}
		if !ts.verifyAuth(conn) {
			conn.Close()
			continue
		}
		ts.mu.Lock()
		if ts.ctrlConn != nil {
			ts.ctrlConn.Close()
		}
		ts.ctrlConn = conn
		ts.mu.Unlock()
		log.Printf("tunnel control connected from %s", conn.RemoteAddr())
	}
}

func (ts *TunnelServer) listenData(ctx context.Context) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", ts.Cfg.DataPort))
	if err != nil {
		log.Printf("tunnel data listen error: %v", err)
		return
	}
	log.Printf("tunnel data listening on :%d", ts.Cfg.DataPort)
	for {
		_, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("data accept error (ignored): %v", err)
		}
	}
}

func (ts *TunnelServer) listenPublic(ctx context.Context) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", ts.Cfg.PublicPort))
	if err != nil {
		log.Printf("public listen error: %v", err)
		return
	}
	log.Printf("public exposed port on :%d -> client target %s", ts.Cfg.PublicPort, ts.Cfg.LocalTarget)
	for {
		pubConn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("public accept error: %v", err)
			continue
		}
		go ts.handlePublic(ctx, pubConn)
	}
}

func (ts *TunnelServer) handlePublic(ctx context.Context, pubConn net.Conn) {
	ts.mu.Lock()
	ctrl := ts.ctrlConn
	ts.mu.Unlock()
	if ctrl == nil {
		log.Printf("no client connected, dropping public conn from %s", pubConn.RemoteAddr())
		pubConn.Close()
		return
	}
	// ask client to dial data channel and local target
	if _, err := ctrl.Write([]byte{0x01}); err != nil {
		log.Printf("control write error: %v", err)
		pubConn.Close()
		return
	}

	dataConn, err := waitDataConn(ctx, ts.Cfg)
	if err != nil {
		log.Printf("wait data conn error: %v", err)
		pubConn.Close()
		return
	}
	defer dataConn.Close()

	if !ts.verifyAuth(dataConn) {
		pubConn.Close()
		return
	}
	if err := pipeEncrypted(pubConn, dataConn, ts.Cfg.Secret); err != nil {
		log.Printf("pipe error: %v", err)
	}
}

func waitDataConn(ctx context.Context, cfg TunnelConfig) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	for {
		conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf(":%d", cfg.DataPort))
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// ================= Tunnel Client =================

type TunnelClient struct {
	Cfg TunnelConfig
}

func (tc *TunnelClient) Start(ctx context.Context) error {
	go tc.controlLoop(ctx)
	return nil
}

func (tc *TunnelClient) controlLoop(ctx context.Context) {
	for {
		if err := tc.runOnce(ctx); err != nil {
			log.Printf("tunnel client run error: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(tc.Cfg.ReconnectSec) * time.Second):
		}
	}
}

func (tc *TunnelClient) runOnce(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", tc.Cfg.ServerAddr, tc.Cfg.ControlPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	if !sendAuth(conn, tc.Cfg.Secret) {
		conn.Close()
		return errors.New("auth failed")
	}
	log.Printf("tunnel client connected to control %s", addr)
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		if buf[0] == 0x01 {
			go tc.spawnDataChannel(ctx)
		}
	}
}

func (tc *TunnelClient) spawnDataChannel(ctx context.Context) {
	dataAddr := fmt.Sprintf("%s:%d", tc.Cfg.ServerAddr, tc.Cfg.DataPort)
	dconn, err := net.Dial("tcp", dataAddr)
	if err != nil {
		log.Printf("data dial error: %v", err)
		return
	}
	if !sendAuth(dconn, tc.Cfg.Secret) {
		dconn.Close()
		return
	}
	localConn, err := net.Dial("tcp", tc.Cfg.LocalTarget)
	if err != nil {
		log.Printf("local dial error: %v", err)
		dconn.Close()
		return
	}
	defer localConn.Close()
	if err := pipeEncrypted(localConn, dconn, tc.Cfg.Secret); err != nil {
		log.Printf("pipe error: %v", err)
	}
}

// ================= helpers =================

func sendAuth(conn net.Conn, secret string) bool {
	hash := sha256.Sum256([]byte(secret))
	if _, err := conn.Write(hash[:]); err != nil {
		return false
	}
	return true
}

func (ts *TunnelServer) verifyAuth(conn net.Conn) bool {
	expected := sha256.Sum256([]byte(ts.Cfg.Secret))
	var got [32]byte
	if _, err := io.ReadFull(conn, got[:]); err != nil {
		log.Printf("auth read error: %v", err)
		return false
	}
	if got != expected {
		log.Printf("auth failed from %s", conn.RemoteAddr())
		return false
	}
	return true
}

func deriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func pipeEncrypted(a, b net.Conn, secret string) error {
	key := deriveKey(secret)

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	// IV for both directions; simple CTR
	ivA := make([]byte, aes.BlockSize)
	ivB := make([]byte, aes.BlockSize)
	if _, err := rand.Read(ivA); err != nil {
		return err
	}
	if _, err := rand.Read(ivB); err != nil {
		return err
	}
	if _, err := b.Write(ivA); err != nil {
		return err
	}
	if _, err := b.Write(ivB); err != nil {
		return err
	}

	streamA := cipher.NewCTR(aesBlock, ivA)
	streamB := cipher.NewCTR(aesBlock, ivB)

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(cipher.StreamWriter{S: streamA, W: b}, a)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(a, cipher.StreamReader{S: streamB, R: b})
		errCh <- err
	}()
	err1 := <-errCh
	err2 := <-errCh
	if err1 != nil && !errors.Is(err1, net.ErrClosed) {
		return err1
	}
	if err2 != nil && !errors.Is(err2, net.ErrClosed) {
		return err2
	}
	return nil
}

func envOr(key, def string) string {
	v := strings.TrimSpace(strings.Trim(os.Getenv(key), " "))
	if v == "" {
		return def
	}
	return v
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}
