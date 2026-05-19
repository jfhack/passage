package tunnel

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

var pqCurvePreferences = []tls.CurveID{tls.X25519MLKEM768}

func serverTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: load keypair: %w", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: pqCurvePreferences,
		Certificates:     []tls.Certificate{cert},
		VerifyConnection: requirePQCurve,
	}, nil
}

func clientTLSConfig(expectedFingerprint string) (*tls.Config, error) {
	want, err := parseFingerprint(expectedFingerprint)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences:   pqCurvePreferences,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tls: no peer certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if got != want {
				return fmt.Errorf("tls: server fingerprint mismatch: got sha256:%s, want %s",
					hex.EncodeToString(got[:]), expectedFingerprint)
			}
			return requirePQCurve(cs)
		},
	}, nil
}

func requirePQCurve(cs tls.ConnectionState) error {
	if cs.CurveID != tls.X25519MLKEM768 {
		return fmt.Errorf("tls: refusing non-pq key exchange (negotiated curve %d, want X25519MLKEM768)", cs.CurveID)
	}
	return nil
}

func parseFingerprint(s string) ([32]byte, error) {
	var out [32]byte
	if !strings.HasPrefix(s, "sha256:") {
		return out, fmt.Errorf("fingerprint must be prefixed sha256:")
	}
	h := strings.TrimPrefix(s, "sha256:")
	raw, err := hex.DecodeString(h)
	if err != nil {
		return out, fmt.Errorf("fingerprint: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("fingerprint: want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func FingerprintFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("expected PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
