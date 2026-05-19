package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfhack/passage/internal/auth"
	"github.com/jfhack/passage/internal/config"
)

func generateSelfSignedTLS(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "passage-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func freePorts(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	listeners := make([]net.Listener, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		listeners = append(listeners, ln)
		out = append(out, ln.Addr().String())
	}
	for _, ln := range listeners {
		_ = ln.Close()
	}
	return out
}

func startBackend(t *testing.T, banner string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(banner))
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln
}

func discardLogger() *slog.Logger {
	if os.Getenv("PASSAGE_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestEndToEnd_Tunnel(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedTLS(t, dir)

	pub, priv, err := auth.GenerateKeypair()
	if err != nil {
		t.Fatalf("gen kp: %v", err)
	}
	keyFile := filepath.Join(dir, "client.ed25519")
	if err := auth.WritePrivkeyPEM(keyFile, priv); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	pqPub, _, pqSeed, err := auth.GeneratePQKeypair()
	if err != nil {
		t.Fatalf("gen pq kp: %v", err)
	}
	pqKeyFile := filepath.Join(dir, "client.mldsa")
	if err := auth.WritePQPrivkeyPEM(pqKeyFile, pqSeed); err != nil {
		t.Fatalf("write pq priv: %v", err)
	}

	backend := startBackend(t, "HELLO\n")
	defer backend.Close()
	backendAddr := backend.Addr().String()

	ports := freePorts(t, 2)
	controlAddr := ports[0]
	publicAddr := ports[1]

	srvCfg := &config.ServerConfig{
		Listen: controlAddr,
		TLS:    config.TLSConfig{Cert: certPath, Key: keyPath},
		Clients: []config.ClientEntry{{
			ID:       "test-client",
			Pubkey:   config.StringOrSlice{auth.EncodePubkey(pub)},
			PQPubkey: config.StringOrSlice{auth.EncodePQPubkey(pqPub)},
			Services: []config.ServiceEntry{{
				Name:   "echo",
				Listen: publicAddr,
			}},
		}},
		Limits: config.LimitsConfig{
			MaxStreamsPerClient: 32,
			HandshakeTimeout:    5 * time.Second,
			IdleTimeout:         60 * time.Second,
			HeartbeatInterval:   1 * time.Second,
		},
	}

	server, err := NewServer(srvCfg, discardLogger())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Run(ctx) }()

	waitListening(t, controlAddr, 3*time.Second)

	fp, err := FingerprintFromCertFile(certPath)
	if err != nil {
		t.Fatalf("fp: %v", err)
	}

	cliCfg := &config.ClientConfig{
		Remote:            controlAddr,
		ServerFingerprint: fp,
		Identity: config.IdentityConfig{
			ID:            "test-client",
			PrivkeyFile:   keyFile,
			PQPrivkeyFile: pqKeyFile,
		},
		Services: map[string]string{"echo": backendAddr},
		Reconnect: config.ReconnectConfig{
			InitialBackoff: 200 * time.Millisecond,
			MaxBackoff:     1 * time.Second,
			Jitter:         false,
		},
	}
	client, err := NewClient(cliCfg, discardLogger())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	go func() { _ = client.Run(ctx) }()

	waitListening(t, publicAddr, 5*time.Second)

	conn, err := net.DialTimeout("tcp", publicAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial public: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, 6)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if string(got) != "HELLO\n" {
		t.Fatalf("banner mismatch: %q", got)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo mismatch: %q", echo)
	}
}

func TestAuth_FailsWithWrongKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedTLS(t, dir)

	realPub, _, _ := auth.GenerateKeypair()
	_, fakePriv, _ := auth.GenerateKeypair()
	fakeKey := filepath.Join(dir, "fake.ed25519")
	if err := auth.WritePrivkeyPEM(fakeKey, fakePriv); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	realPQPub, _, _, _ := auth.GeneratePQKeypair()
	_, _, fakePQSeed, _ := auth.GeneratePQKeypair()
	fakePQKey := filepath.Join(dir, "fake.mldsa")
	if err := auth.WritePQPrivkeyPEM(fakePQKey, fakePQSeed); err != nil {
		t.Fatalf("write pq priv: %v", err)
	}

	ports := freePorts(t, 2)
	controlAddr := ports[0]
	publicAddr := ports[1]

	srvCfg := &config.ServerConfig{
		Listen: controlAddr,
		TLS:    config.TLSConfig{Cert: certPath, Key: keyPath},
		Clients: []config.ClientEntry{{
			ID:       "test-client",
			Pubkey:   config.StringOrSlice{auth.EncodePubkey(realPub)},
			PQPubkey: config.StringOrSlice{auth.EncodePQPubkey(realPQPub)},
			Services: []config.ServiceEntry{{Name: "x", Listen: publicAddr}},
		}},
		Limits: config.LimitsConfig{
			HandshakeTimeout:  5 * time.Second,
			IdleTimeout:       60 * time.Second,
			HeartbeatInterval: 1 * time.Second,
		},
	}
	server, err := NewServer(srvCfg, discardLogger())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Run(ctx) }()
	waitListening(t, controlAddr, 3*time.Second)

	fp, _ := FingerprintFromCertFile(certPath)
	cliCfg := &config.ClientConfig{
		Remote:            controlAddr,
		ServerFingerprint: fp,
		Identity:          config.IdentityConfig{ID: "test-client", PrivkeyFile: fakeKey, PQPrivkeyFile: fakePQKey},
		Services:          map[string]string{"x": "127.0.0.1:1"},
		Reconnect:         config.ReconnectConfig{InitialBackoff: 100 * time.Millisecond, MaxBackoff: time.Second},
	}
	client, err := NewClient(cliCfg, discardLogger())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	verCtx, verCancel := context.WithTimeout(ctx, 5*time.Second)
	defer verCancel()
	if err := client.VerifyOnce(verCtx); err == nil {
		t.Fatal("expected auth failure with wrong key")
	}
}

func TestAuth_FailsOnFingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedTLS(t, dir)
	pub, priv, _ := auth.GenerateKeypair()
	keyFile := filepath.Join(dir, "client.ed25519")
	_ = auth.WritePrivkeyPEM(keyFile, priv)
	pqPub, _, pqSeed, _ := auth.GeneratePQKeypair()
	pqKeyFile := filepath.Join(dir, "client.mldsa")
	_ = auth.WritePQPrivkeyPEM(pqKeyFile, pqSeed)

	ports := freePorts(t, 2)
	controlAddr := ports[0]
	publicAddr := ports[1]
	srvCfg := &config.ServerConfig{
		Listen: controlAddr,
		TLS:    config.TLSConfig{Cert: certPath, Key: keyPath},
		Clients: []config.ClientEntry{{
			ID:       "c",
			Pubkey:   config.StringOrSlice{auth.EncodePubkey(pub)},
			PQPubkey: config.StringOrSlice{auth.EncodePQPubkey(pqPub)},
			Services: []config.ServiceEntry{{Name: "x", Listen: publicAddr}},
		}},
		Limits: config.LimitsConfig{
			HandshakeTimeout:  5 * time.Second,
			IdleTimeout:       60 * time.Second,
			HeartbeatInterval: 1 * time.Second,
		},
	}
	server, err := NewServer(srvCfg, discardLogger())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Run(ctx) }()
	waitListening(t, controlAddr, 3*time.Second)

	wrong := "sha256:" + strings.Repeat("0", 64)
	cliCfg := &config.ClientConfig{
		Remote:            controlAddr,
		ServerFingerprint: wrong,
		Identity:          config.IdentityConfig{ID: "c", PrivkeyFile: keyFile, PQPrivkeyFile: pqKeyFile},
		Services:          map[string]string{"x": "127.0.0.1:1"},
		Reconnect:         config.ReconnectConfig{InitialBackoff: 100 * time.Millisecond, MaxBackoff: time.Second},
	}
	client, err := NewClient(cliCfg, discardLogger())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	verCtx, verCancel := context.WithTimeout(ctx, 5*time.Second)
	defer verCancel()
	if err := client.VerifyOnce(verCtx); err == nil {
		t.Fatal("expected fingerprint failure")
	}
}

func waitListening(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s within %s", addr, timeout)
}
