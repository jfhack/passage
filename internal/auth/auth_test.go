package auth

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	nonce := []byte("0123456789abcdef0123456789abcdef")
	exp := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	now := time.Now().Unix()
	sig := Sign(priv, nonce, exp, "client-a", now)
	if err := Verify([]ed25519.PublicKey{pub}, sig, nonce, exp, "client-a", now); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerify_RejectsTampering(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	nonce := []byte("0123456789abcdef0123456789abcdef")
	exp := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	now := time.Now().Unix()
	sig := Sign(priv, nonce, exp, "client-a", now)

	cases := []struct {
		name string
		mut  func(*[]byte, *[]byte, *string, *int64)
	}{
		{"different exporter", func(_, e *[]byte, _ *string, _ *int64) { (*e)[0] ^= 0x01 }},
		{"different nonce", func(n, _ *[]byte, _ *string, _ *int64) { (*n)[0] ^= 0x01 }},
		{"different client id", func(_, _ *[]byte, c *string, _ *int64) { *c = "other" }},
		{"different time", func(_, _ *[]byte, _ *string, ts *int64) { *ts++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := append([]byte(nil), nonce...)
			e := append([]byte(nil), exp...)
			id := "client-a"
			ts := now
			tc.mut(&n, &e, &id, &ts)
			if err := Verify([]ed25519.PublicKey{pub}, sig, n, e, id, ts); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("expected ErrBadSignature, got %v", err)
			}
		})
	}
}

func TestVerify_TriesEachKey(t *testing.T) {
	_, oldPriv, _ := GenerateKeypair()
	pubNew, privNew, _ := GenerateKeypair()
	pubOther, _, _ := GenerateKeypair()

	nonce := []byte("0123456789abcdef0123456789abcdef")
	exp := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	now := time.Now().Unix()
	sig := Sign(privNew, nonce, exp, "id", now)
	_ = oldPriv

	pubs := []ed25519.PublicKey{pubOther, pubNew}
	if err := Verify(pubs, sig, nonce, exp, "id", now); err != nil {
		t.Fatalf("rotation list verify: %v", err)
	}
	pubsBad := []ed25519.PublicKey{pubOther}
	if err := Verify(pubsBad, sig, nonce, exp, "id", now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected fail without correct key, got %v", err)
	}
}

func TestCheckClockSkew(t *testing.T) {
	now := time.Now()
	if err := CheckClockSkew(now, now.Unix()); err != nil {
		t.Errorf("zero skew: %v", err)
	}
	if err := CheckClockSkew(now, now.Add(30*time.Second).Unix()); err != nil {
		t.Errorf("30s ahead: %v", err)
	}
	if err := CheckClockSkew(now, now.Add(2*time.Minute).Unix()); !errors.Is(err, ErrClockSkew) {
		t.Errorf("2m ahead should fail, got %v", err)
	}
	if err := CheckClockSkew(now, now.Add(-2*time.Minute).Unix()); !errors.Is(err, ErrClockSkew) {
		t.Errorf("2m behind should fail, got %v", err)
	}
}

func TestEncodeDecodePubkey(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	enc := EncodePubkey(pub)
	got, err := DecodePubkey(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != string(pub) {
		t.Fatal("round-trip mismatch")
	}
}

func TestDecodePubkey_RejectsGarbage(t *testing.T) {
	if _, err := DecodePubkey("rsa:abc"); !errors.Is(err, ErrBadKeyFormat) {
		t.Errorf("wrong prefix should fail, got %v", err)
	}
	if _, err := DecodePubkey("ed25519:!!!"); !errors.Is(err, ErrBadKeyFormat) {
		t.Errorf("garbage base64 should fail, got %v", err)
	}
}

func TestPrivkeyPEM_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k.pem")
	_, priv, _ := GenerateKeypair()
	if err := WritePrivkeyPEM(p, priv); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadPrivkeyPEM(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != string(priv) {
		t.Fatal("round-trip mismatch")
	}
}

func TestNewNonce_LengthAndEntropy(t *testing.T) {
	n1, err := NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	n2, _ := NewNonce()
	if len(n1) != 32 {
		t.Fatalf("len: %d", len(n1))
	}
	if string(n1) == string(n2) {
		t.Fatal("nonce repeats")
	}
}
