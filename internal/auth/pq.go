package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/jfhack/passage/internal/proto"
)

const PQAlgorithmMLDSA = "mldsa"

const PQPubkeyPrefix = "mldsa:"

const PQPrivkeyPEMType = "PASSAGE ML-DSA-65 PRIVATE KEY"

const PQAuthLabel = proto.PQAuthLabel

const PQSeedSize = 32

var (
	ErrPQUnknownAlgorithm = errors.New("auth: unknown pq_algorithm")
	ErrPQRequired         = errors.New("auth: pq signature required but missing")
	ErrPQBadSignature     = errors.New("auth: pq signature verification failed")
)

func PQSigningInput(nonce, exporter []byte, clientID string, clientTime int64, requested []string) []byte {
	var b []byte
	b = appendLengthPrefixed(b, nonce)
	b = appendLengthPrefixed(b, exporter)
	b = appendLengthPrefixed(b, []byte(clientID))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(clientTime))
	b = append(b, ts[:]...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(requested)))
	b = append(b, n[:]...)
	for _, s := range requested {
		b = appendLengthPrefixed(b, []byte(s))
	}
	return b
}

func appendLengthPrefixed(dst, src []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(src)))
	dst = append(dst, n[:]...)
	dst = append(dst, src...)
	return dst
}

func PQSign(sk *mldsa65.PrivateKey, nonce, exporter []byte, clientID string, clientTime int64, requested []string) ([]byte, error) {
	msg := PQSigningInput(nonce, exporter, clientID, clientTime, requested)
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, msg, []byte(PQAuthLabel), false, sig); err != nil {
		return nil, fmt.Errorf("auth: pq sign: %w", err)
	}
	return sig, nil
}

func PQVerify(pubs []*mldsa65.PublicKey, sig, nonce, exporter []byte, clientID string, clientTime int64, requested []string) error {
	if len(sig) != mldsa65.SignatureSize {
		return ErrPQBadSignature
	}
	msg := PQSigningInput(nonce, exporter, clientID, clientTime, requested)
	for _, pk := range pubs {
		if pk == nil {
			continue
		}
		if mldsa65.Verify(pk, msg, []byte(PQAuthLabel), sig) {
			return nil
		}
	}
	return ErrPQBadSignature
}

func EncodePQPubkey(pub *mldsa65.PublicKey) string {
	raw, _ := pub.MarshalBinary()
	return PQPubkeyPrefix + base64.StdEncoding.EncodeToString(raw)
}

func DecodePQPubkey(s string) (*mldsa65.PublicKey, error) {
	if !strings.HasPrefix(s, PQPubkeyPrefix) {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrBadKeyFormat, PQPubkeyPrefix)
	}
	body := strings.TrimPrefix(s, PQPubkeyPrefix)
	for _, dec := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if raw, err := dec.DecodeString(body); err == nil && len(raw) == mldsa65.PublicKeySize {
			pk := new(mldsa65.PublicKey)
			if err := pk.UnmarshalBinary(raw); err == nil {
				return pk, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: invalid base64 or wrong length for ML-DSA-65 public key", ErrBadKeyFormat)
}

func GeneratePQKeypair() (*mldsa65.PublicKey, *mldsa65.PrivateKey, []byte, error) {
	var seed [PQSeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, nil, err
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return pk, sk, seed[:], nil
}

func WritePQPrivkeyPEM(path string, seed []byte) error {
	if len(seed) != PQSeedSize {
		return fmt.Errorf("auth: bad ML-DSA seed length %d", len(seed))
	}
	block := &pem.Block{
		Type:  PQPrivkeyPEMType,
		Bytes: append([]byte(nil), seed...),
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

func LoadPQPrivkeyPEM(path string) (*mldsa65.PublicKey, *mldsa65.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != PQPrivkeyPEMType {
		return nil, nil, fmt.Errorf("%w: expected PEM block %q", ErrBadKeyFormat, PQPrivkeyPEMType)
	}
	if len(block.Bytes) != PQSeedSize {
		return nil, nil, fmt.Errorf("%w: ML-DSA seed length %d", ErrBadKeyFormat, len(block.Bytes))
	}
	var seed [PQSeedSize]byte
	copy(seed[:], block.Bytes)
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return pk, sk, nil
}
