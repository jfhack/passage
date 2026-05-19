package auth

import (
	"crypto/ed25519"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var (
	benchNonce    = []byte("0123456789abcdef0123456789abcdef")
	benchExporter = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	benchClientID = "bench-client"
	benchTime     = int64(1735000000)
	benchSvcs     = []string{"ssh", "pg"}
)

func BenchmarkEd25519Handshake(b *testing.B) {
	pub, priv, _ := GenerateKeypair()
	pubs := []ed25519.PublicKey{pub}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig := Sign(priv, benchNonce, benchExporter, benchClientID, benchTime)
		if err := Verify(pubs, sig, benchNonce, benchExporter, benchClientID, benchTime); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLDSAHandshake(b *testing.B) {
	pub, sk, _, _ := GeneratePQKeypair()
	pubs := []*mldsa65.PublicKey{pub}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := PQSign(sk, benchNonce, benchExporter, benchClientID, benchTime, benchSvcs)
		if err != nil {
			b.Fatal(err)
		}
		if err := PQVerify(pubs, sig, benchNonce, benchExporter, benchClientID, benchTime, benchSvcs); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHybridHandshake(b *testing.B) {
	edPub, edPriv, _ := GenerateKeypair()
	edPubs := []ed25519.PublicKey{edPub}
	pqPub, pqSk, _, _ := GeneratePQKeypair()
	pqPubs := []*mldsa65.PublicKey{pqPub}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		edSig := Sign(edPriv, benchNonce, benchExporter, benchClientID, benchTime)
		pqSig, err := PQSign(pqSk, benchNonce, benchExporter, benchClientID, benchTime, benchSvcs)
		if err != nil {
			b.Fatal(err)
		}
		if err := Verify(edPubs, edSig, benchNonce, benchExporter, benchClientID, benchTime); err != nil {
			b.Fatal(err)
		}
		if err := PQVerify(pqPubs, pqSig, benchNonce, benchExporter, benchClientID, benchTime, benchSvcs); err != nil {
			b.Fatal(err)
		}
	}
}
