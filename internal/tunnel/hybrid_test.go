package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfhack/passage/internal/auth"
	"github.com/jfhack/passage/internal/config"
	"github.com/jfhack/passage/internal/proto"
)

type hybridFixture struct {
	dir         string
	controlAddr string
	publicAddr  string
	fingerprint string
	clientID    string
	edKeyFile   string
	pqKeyFile   string
}

func startHybridServer(t *testing.T, extraPQPubs []string) *hybridFixture {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedTLS(t, dir)

	pub, priv, _ := auth.GenerateKeypair()
	edKeyFile := filepath.Join(dir, "client.ed25519")
	if err := auth.WritePrivkeyPEM(edKeyFile, priv); err != nil {
		t.Fatalf("write ed priv: %v", err)
	}
	pqPub, _, pqSeed, _ := auth.GeneratePQKeypair()
	pqKeyFile := filepath.Join(dir, "client.mldsa")
	if err := auth.WritePQPrivkeyPEM(pqKeyFile, pqSeed); err != nil {
		t.Fatalf("write pq priv: %v", err)
	}

	ports := freePorts(t, 2)
	controlAddr := ports[0]
	publicAddr := ports[1]

	clientID := "hybrid-client"
	entry := config.ClientEntry{
		ID:       clientID,
		Pubkey:   config.StringOrSlice{auth.EncodePubkey(pub)},
		PQPubkey: append(config.StringOrSlice{auth.EncodePQPubkey(pqPub)}, extraPQPubs...),
		Services: []config.ServiceEntry{{
			Name:   "echo",
			Listen: publicAddr,
		}},
	}

	srvCfg := &config.ServerConfig{
		Listen:  controlAddr,
		TLS:     config.TLSConfig{Cert: certPath, Key: keyPath},
		Clients: []config.ClientEntry{entry},
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
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx) }()
	waitListening(t, controlAddr, 3*time.Second)

	fp, err := FingerprintFromCertFile(certPath)
	if err != nil {
		t.Fatalf("fp: %v", err)
	}
	return &hybridFixture{
		dir:         dir,
		controlAddr: controlAddr,
		publicAddr:  publicAddr,
		fingerprint: fp,
		clientID:    clientID,
		edKeyFile:   edKeyFile,
		pqKeyFile:   pqKeyFile,
	}
}

func (h *hybridFixture) clientCfg(pqKeyOverride string) *config.ClientConfig {
	pqKey := h.pqKeyFile
	if pqKeyOverride != "" {
		pqKey = pqKeyOverride
	}
	return &config.ClientConfig{
		Remote:            h.controlAddr,
		ServerFingerprint: h.fingerprint,
		Identity: config.IdentityConfig{
			ID:            h.clientID,
			PrivkeyFile:   h.edKeyFile,
			PQPrivkeyFile: pqKey,
		},
		Services:  map[string]string{"echo": "127.0.0.1:1"},
		Reconnect: config.ReconnectConfig{InitialBackoff: 100 * time.Millisecond, MaxBackoff: time.Second},
	}
}

func TestHybridAuth_Succeeds(t *testing.T) {
	h := startHybridServer(t, nil)
	client, err := NewClient(h.clientCfg(""), discardLogger())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	verCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.VerifyOnce(verCtx); err != nil {
		t.Fatalf("hybrid verify: %v", err)
	}
}

func TestHybridAuth_BadPQSignatureFails(t *testing.T) {
	h := startHybridServer(t, nil)
	_, _, otherSeed, _ := auth.GeneratePQKeypair()
	wrongKey := filepath.Join(h.dir, "wrong.mldsa")
	if err := auth.WritePQPrivkeyPEM(wrongKey, otherSeed); err != nil {
		t.Fatalf("write wrong pq priv: %v", err)
	}
	client, err := NewClient(h.clientCfg(wrongKey), discardLogger())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	verCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.VerifyOnce(verCtx); err == nil {
		t.Fatal("expected failure with wrong pq key")
	}
}

func TestHybridAuth_KeyRotation(t *testing.T) {
	otherPub, _, _, _ := auth.GeneratePQKeypair()
	h := startHybridServer(t, []string{auth.EncodePQPubkey(otherPub)})
	client, err := NewClient(h.clientCfg(""), discardLogger())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	verCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.VerifyOnce(verCtx); err != nil {
		t.Fatalf("rotation list verify: %v", err)
	}
}

func TestHybridAuth_MissingPQFails(t *testing.T) {
	h := startHybridServer(t, nil)
	priv, err := auth.LoadPrivkeyPEM(h.edKeyFile)
	if err != nil {
		t.Fatalf("load ed priv: %v", err)
	}
	conn, hello, exporter := dialAndHello(t, h)
	defer conn.Close()

	now := time.Now().Unix()
	requested := []string{"echo"}
	ca := proto.ClientAuth{
		ClientID:          h.clientID,
		ClientTime:        now,
		Signature:         auth.Sign(priv, hello.Nonce, exporter, h.clientID, now),
		RequestedServices: requested,
	}
	if err := proto.WriteMessage(conn, ca); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	var acc proto.Accepted
	if err := proto.ReadMessage(conn, &acc); err == nil && acc.SessionID != "" {
		t.Fatal("server accepted ClientAuth without PQ signature")
	}
}

func TestHybridAuth_UnknownPQAlgorithmFails(t *testing.T) {
	h := startHybridServer(t, nil)
	priv, err := auth.LoadPrivkeyPEM(h.edKeyFile)
	if err != nil {
		t.Fatalf("load ed priv: %v", err)
	}
	conn, hello, exporter := dialAndHello(t, h)
	defer conn.Close()

	now := time.Now().Unix()
	requested := []string{"echo"}
	ca := proto.ClientAuth{
		ClientID:          h.clientID,
		ClientTime:        now,
		Signature:         auth.Sign(priv, hello.Nonce, exporter, h.clientID, now),
		RequestedServices: requested,
		PQAlgorithm:       "falcon",
		PQSignature:       []byte("xxxxx"),
	}
	if err := proto.WriteMessage(conn, ca); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	var acc proto.Accepted
	if err := proto.ReadMessage(conn, &acc); err == nil && acc.SessionID != "" {
		t.Fatal("server accepted unknown pq_algorithm")
	}
}

func dialAndHello(t *testing.T, h *hybridFixture) (*tls.Conn, proto.ServerHello, []byte) {
	t.Helper()
	tlsCfg, err := clientTLSConfig(h.fingerprint)
	if err != nil {
		t.Fatalf("tls cfg: %v", err)
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.Dial("tcp", h.controlAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := tls.Client(raw, tlsCfg)
	hsCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close()
		t.Fatalf("tls handshake: %v", err)
	}
	cs := conn.ConnectionState()
	exporter, err := cs.ExportKeyingMaterial(proto.AuthLabel, nil, proto.ExporterLength)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("exporter: %v", err)
	}
	var hello proto.ServerHello
	if err := proto.ReadMessage(conn, &hello); err != nil {
		_ = conn.Close()
		t.Fatalf("read hello: %v", err)
	}
	return conn, hello, exporter
}
