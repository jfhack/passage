#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${PASSAGE_IMAGE:-ghcr.io/jfhack/passage:latest}"

mkdir -p keys
docker pull "${IMAGE}" >/dev/null

if [[ ! -f keys/client.ed25519 || ! -f keys/client.mldsa ]]; then
  docker run --rm --user 0:0 -v "$(pwd)/keys":/keys "${IMAGE}" \
    keygen -out /keys/client.ed25519 -pq-out /keys/client.mldsa | tee keys/keygen.out
  docker run --rm -v "$(pwd)/keys":/keys alpine:3 sh -c '
    chown 65532:65532 /keys/client.ed25519 /keys/client.mldsa
    chmod 0600 /keys/client.ed25519 /keys/client.mldsa
  '
fi

PUBKEY="$(grep -E '^ed25519:' keys/keygen.out | head -1)"
PQ_PUBKEY="$(grep -E '^mldsa:' keys/keygen.out | head -1)"

echo
echo "================================================================"
echo "  client public keys (give both to the server admin):"
echo "    ${PUBKEY}"
echo "    ${PQ_PUBKEY}"
echo "================================================================"
echo

DEFAULT_ID="$(hostname -s 2>/dev/null || hostname)"
read -r -p "client id [${DEFAULT_ID}]: " CLID
CLID="${CLID:-${DEFAULT_ID}}"
read -r -p "remote server (host:port): " REMOTE
read -r -p "server fingerprint (sha256:<hex>): " FP

if [[ -z "${REMOTE}" || -z "${FP}" ]]; then
  echo "remote and fingerprint are both required." >&2
  exit 1
fi
if [[ "${FP}" != sha256:* ]]; then
  echo "fingerprint must start with 'sha256:'" >&2
  exit 1
fi

sed -i.bak -E "s|id: REPLACE_ME_CLIENT_ID|id: ${CLID}|" client.yaml
sed -i.bak -E "s|remote: REPLACE_ME_REMOTE|remote: ${REMOTE}|" client.yaml
sed -i.bak -E "s|server_fingerprint: sha256:REPLACE_ME_FINGERPRINT|server_fingerprint: ${FP}|" client.yaml
rm -f client.yaml.bak

echo "==> client.yaml patched. start with: docker compose up -d"
