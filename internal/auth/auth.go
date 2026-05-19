package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jfhack/passage/internal/proto"
)

const PubkeyPrefix = "ed25519:"

const PrivkeyPEMType = "PASSAGE ED25519 PRIVATE KEY"

const MaxClockSkew = 60 * time.Second

var (
	ErrUnknownClient   = errors.New("auth: unknown client id")
	ErrBadSignature    = errors.New("auth: signature verification failed")
	ErrClockSkew       = errors.New("auth: client_time outside permitted skew window")
	ErrServiceNotAllow = errors.New("auth: requested service not in allowlist")
	ErrBadKeyFormat    = errors.New("auth: malformed key encoding")
)

func SigningInput(nonce, exporter []byte, clientID string, clientTime int64) []byte {
	out := make([]byte, 0, len(nonce)+len(exporter)+len(clientID)+8)
	out = append(out, nonce...)
	out = append(out, exporter...)
	out = append(out, clientID...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(clientTime))
	out = append(out, ts[:]...)
	return out
}

func Sign(priv ed25519.PrivateKey, nonce, exporter []byte, clientID string, clientTime int64) []byte {
	return ed25519.Sign(priv, SigningInput(nonce, exporter, clientID, clientTime))
}

func Verify(pubs []ed25519.PublicKey, sig, nonce, exporter []byte, clientID string, clientTime int64) error {
	if len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	msg := SigningInput(nonce, exporter, clientID, clientTime)
	for _, pub := range pubs {
		if len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, sig) {
			return nil
		}
	}
	return ErrBadSignature
}

func CheckClockSkew(serverNow time.Time, clientTime int64) error {
	delta := serverNow.Sub(time.Unix(clientTime, 0))
	if delta < 0 {
		delta = -delta
	}
	if delta > MaxClockSkew {
		return ErrClockSkew
	}
	return nil
}

func NewNonce() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func EncodePubkey(pub ed25519.PublicKey) string {
	return PubkeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

func DecodePubkey(s string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(s, PubkeyPrefix) {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrBadKeyFormat, PubkeyPrefix)
	}
	body := strings.TrimPrefix(s, PubkeyPrefix)
	for _, dec := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if raw, err := dec.DecodeString(body); err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, fmt.Errorf("%w: invalid base64 or wrong length", ErrBadKeyFormat)
}

func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func WritePrivkeyPEM(path string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("auth: bad private key length %d", len(priv))
	}
	block := &pem.Block{
		Type:  PrivkeyPEMType,
		Bytes: priv.Seed(),
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

func LoadPrivkeyPEM(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != PrivkeyPEMType {
		return nil, fmt.Errorf("%w: expected PEM block %q", ErrBadKeyFormat, PrivkeyPEMType)
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed length %d", ErrBadKeyFormat, len(block.Bytes))
	}
	return ed25519.NewKeyFromSeed(block.Bytes), nil
}

func FormatFingerprint(sum [32]byte) string {
	return "sha256:" + hex.EncodeToString(sum[:])
}

const ExporterLabel = proto.AuthLabel
