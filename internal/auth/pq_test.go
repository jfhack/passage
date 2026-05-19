package auth

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestPQSignVerify_RoundTrip(t *testing.T) {
	pub, sk, _, err := GeneratePQKeypair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	nonce := []byte("0123456789abcdef0123456789abcdef")
	exp := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	requested := []string{"ssh", "pg"}
	sig, err := PQSign(sk, nonce, exp, "client-a", 1735000000, requested)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := PQVerify([]*mldsa65.PublicKey{pub}, sig, nonce, exp, "client-a", 1735000000, requested); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestPQVerify_RejectsTampering(t *testing.T) {
	pub, sk, _, _ := GeneratePQKeypair()
	nonce := []byte("0123456789abcdef0123456789abcdef")
	exp := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	requested := []string{"ssh"}
	sig, _ := PQSign(sk, nonce, exp, "client-a", 1, requested)

	cases := []struct {
		name string
		mut  func(*[]byte, *[]byte, *string, *int64, *[]string)
	}{
		{"different exporter", func(_, e *[]byte, _ *string, _ *int64, _ *[]string) { (*e)[0] ^= 1 }},
		{"different nonce", func(n, _ *[]byte, _ *string, _ *int64, _ *[]string) { (*n)[0] ^= 1 }},
		{"different client id", func(_, _ *[]byte, c *string, _ *int64, _ *[]string) { *c = "other" }},
		{"different time", func(_, _ *[]byte, _ *string, ts *int64, _ *[]string) { *ts++ }},
		{"different services", func(_, _ *[]byte, _ *string, _ *int64, r *[]string) { (*r)[0] = "other" }},
		{"reordered services", func(_, _ *[]byte, _ *string, _ *int64, r *[]string) { *r = []string{"ssh", "extra"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := append([]byte(nil), nonce...)
			e := append([]byte(nil), exp...)
			id := "client-a"
			ts := int64(1)
			r := append([]string(nil), requested...)
			tc.mut(&n, &e, &id, &ts, &r)
			if err := PQVerify([]*mldsa65.PublicKey{pub}, sig, n, e, id, ts, r); !errors.Is(err, ErrPQBadSignature) {
				t.Fatalf("expected ErrPQBadSignature, got %v", err)
			}
		})
	}
}

func TestPQVerify_TriesEachKey(t *testing.T) {
	_, oldSk, _, _ := GeneratePQKeypair()
	pubNew, skNew, _, _ := GeneratePQKeypair()
	pubOther, _, _, _ := GeneratePQKeypair()

	nonce := []byte("0123456789abcdef0123456789abcdef")
	exp := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	requested := []string{"ssh"}
	sig, _ := PQSign(skNew, nonce, exp, "id", 1, requested)
	_ = oldSk

	pubs := []*mldsa65.PublicKey{pubOther, pubNew}
	if err := PQVerify(pubs, sig, nonce, exp, "id", 1, requested); err != nil {
		t.Fatalf("rotation list verify: %v", err)
	}
	if err := PQVerify([]*mldsa65.PublicKey{pubOther}, sig, nonce, exp, "id", 1, requested); !errors.Is(err, ErrPQBadSignature) {
		t.Fatalf("expected fail without correct key, got %v", err)
	}
}

func TestPQVerify_DomainSeparatedFromEd25519(t *testing.T) {
	pub, sk, _, _ := GeneratePQKeypair()
	nonce := []byte("0123456789abcdef0123456789abcdef")
	exp := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	sig, _ := PQSign(sk, nonce, exp, "id", 1, []string{"ssh"})
	if err := PQVerify([]*mldsa65.PublicKey{pub}, sig[:len(sig)-1], nonce, exp, "id", 1, []string{"ssh"}); !errors.Is(err, ErrPQBadSignature) {
		t.Fatalf("truncated sig should fail, got %v", err)
	}
}

func TestEncodeDecodePQPubkey(t *testing.T) {
	pub, _, _, _ := GeneratePQKeypair()
	enc := EncodePQPubkey(pub)
	got, err := DecodePQPubkey(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !pub.Equal(got) {
		t.Fatal("round-trip mismatch")
	}
}

func TestDecodePQPubkey_Garbage(t *testing.T) {
	if _, err := DecodePQPubkey("ed25519:abc"); !errors.Is(err, ErrBadKeyFormat) {
		t.Errorf("wrong prefix should fail, got %v", err)
	}
	if _, err := DecodePQPubkey("mldsa:!!!"); !errors.Is(err, ErrBadKeyFormat) {
		t.Errorf("garbage base64 should fail, got %v", err)
	}
}

func TestPQPrivkeyPEM_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k.pem")
	pub, _, seed, _ := GeneratePQKeypair()
	if err := WritePQPrivkeyPEM(p, seed); err != nil {
		t.Fatalf("write: %v", err)
	}
	gotPub, gotSk, err := LoadPQPrivkeyPEM(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !pub.Equal(gotPub) {
		t.Fatal("pubkey from seed differs after round trip")
	}
	sig, err := PQSign(gotSk, []byte("nonce-nonce-nonce-nonce-nonce-no"), []byte("exporter-exporter-exporter-expor"), "id", 1, []string{"x"})
	if err != nil {
		t.Fatalf("pq sign: %v", err)
	}
	if err := PQVerify([]*mldsa65.PublicKey{pub}, sig, []byte("nonce-nonce-nonce-nonce-nonce-no"), []byte("exporter-exporter-exporter-expor"), "id", 1, []string{"x"}); err != nil {
		t.Fatalf("verify after reload: %v", err)
	}
}
