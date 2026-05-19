#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p keys
ROOT="$(cd ../.. && pwd)"

docker run --rm -v "${ROOT}":/src -w /src golang:1.26-alpine \
  sh -c 'go build -trimpath -ldflags="-s -w" -o /tmp/passage ./cmd/passage \
         && cp /tmp/passage /src/quick/isolated/keys/passage'

if [[ ! -f keys/server.crt ]]; then
  echo "==> generating self-signed TLS cert"
  docker run --rm -v "$(pwd)/keys":/k alpine:3 sh -c '
    apk add --no-cache openssl >/dev/null
    openssl req -x509 -newkey ed25519 -nodes -subj "/CN=passage" \
      -keyout /k/server.key -out /k/server.crt -days 825
    chmod 0600 /k/server.key
  '
fi

if [[ ! -f keys/client.ed25519 || ! -f keys/client.mldsa ]]; then
  echo "==> generating hybrid Ed25519 + ML-DSA-65 client keypair"
  ./keys/passage keygen \
    -out ./keys/client.ed25519 \
    -pq-out ./keys/client.mldsa | tee keys/keygen.out
fi

PUBKEY="$(grep -E '^ed25519:' keys/keygen.out | head -1)"
PQ_PUBKEY="$(grep -E '^mldsa:' keys/keygen.out | head -1)"
FP="$(./keys/passage fingerprint keys/server.crt)"

echo "==> patching server.yaml with pubkey ${PUBKEY:0:24}..."
sed -i.bak -E "s|pubkey: ed25519:.*|pubkey: ${PUBKEY}|" server.yaml
echo "==> patching server.yaml with pq_pubkey ${PQ_PUBKEY:0:18}..."
sed -i.bak -E "s|pq_pubkey: mldsa:.*|pq_pubkey: ${PQ_PUBKEY}|" server.yaml
echo "==> patching client.yaml with fingerprint ${FP:0:20}..."
sed -i.bak -E "s|server_fingerprint: sha256:.*|server_fingerprint: ${FP}|" client.yaml
rm -f server.yaml.bak client.yaml.bak

echo "==> bootstrap complete. you can now run: docker compose up --build"
