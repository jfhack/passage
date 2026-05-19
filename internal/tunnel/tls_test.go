package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTLS_NegotiatesHybridPQCurve(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedTLS(t, dir)
	srvCfg, err := serverTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("server cfg: %v", err)
	}
	fp, err := FingerprintFromCertFile(certPath)
	if err != nil {
		t.Fatalf("fp: %v", err)
	}
	cliCfg, err := clientTLSConfig(fp)
	if err != nil {
		t.Fatalf("client cfg: %v", err)
	}

	rawL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawL.Close()
	tlsL := tls.NewListener(rawL, srvCfg)

	type result struct {
		curve tls.CurveID
		err   error
	}
	srvDone := make(chan result, 1)
	go func() {
		c, err := tlsL.Accept()
		if err != nil {
			srvDone <- result{err: err}
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(ctx); err != nil {
			srvDone <- result{err: err}
			return
		}
		srvDone <- result{curve: tc.ConnectionState().CurveID}
	}()

	d := net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.Dial("tcp", rawL.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	client := tls.Client(raw, cliCfg)
	hsCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.HandshakeContext(hsCtx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if got := client.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
		t.Fatalf("client side negotiated curve %d, want X25519MLKEM768 (%d)", got, tls.X25519MLKEM768)
	}

	r := <-srvDone
	if r.err != nil {
		t.Fatalf("server handshake: %v", r.err)
	}
	if r.curve != tls.X25519MLKEM768 {
		t.Fatalf("server side negotiated curve %d, want X25519MLKEM768 (%d)", r.curve, tls.X25519MLKEM768)
	}
}

func TestTLS_RefusesClassicalOnlyClient(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedTLS(t, dir)
	srvCfg, err := serverTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("server cfg: %v", err)
	}

	rawL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawL.Close()
	tlsL := tls.NewListener(rawL, srvCfg)

	srvErr := make(chan error, 1)
	go func() {
		c, err := tlsL.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srvErr <- c.(*tls.Conn).HandshakeContext(ctx)
	}()

	classicalCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.Dial("tcp", rawL.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	client := tls.Client(raw, classicalCfg)
	hsCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.HandshakeContext(hsCtx); err == nil {
		t.Fatal("expected handshake failure when client offers only classical curves")
	}
	if err := <-srvErr; err == nil {
		t.Log("server reported no error, but client handshake failed (acceptable)")
	} else if !strings.Contains(err.Error(), "no") && !strings.Contains(err.Error(), "curve") && !strings.Contains(err.Error(), "alert") {
		t.Logf("server error (informational): %v", err)
	}
}
