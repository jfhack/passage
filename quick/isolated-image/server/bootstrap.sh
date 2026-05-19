#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${PASSAGE_IMAGE:-ghcr.io/jfhack/passage:latest}"

mkdir -p keys
docker pull "${IMAGE}" >/dev/null

if [[ ! -f keys/server.crt ]]; then
  docker run --rm -v "$(pwd)/keys":/k alpine:3 sh -c '
    apk add --no-cache openssl >/dev/null
    openssl req -x509 -newkey ed25519 -nodes -subj "/CN=passage" \
      -keyout /k/server.key -out /k/server.crt -days 825
    chown 65532:65532 /k/server.key /k/server.crt
    chmod 0600 /k/server.key
    chmod 0644 /k/server.crt
  '
fi

FP="$(docker run --rm -v "$(pwd)/keys":/keys "${IMAGE}" fingerprint /keys/server.crt)"

echo
echo "================================================================"
echo "  server fingerprint (give this to the client admin):"
echo "    ${FP}"
echo "================================================================"
echo

read -r -p "client id (must match what the client sends): " CLID
read -r -p "client public key (ed25519:...): " PUBKEY
read -r -p "client pq public key (mldsa:...): " PQ_PUBKEY

if [[ -z "${CLID}" || -z "${PUBKEY}" || -z "${PQ_PUBKEY}" ]]; then
  echo "client id, pubkey and pq_pubkey are all required for hybrid auth." >&2
  exit 1
fi
if [[ "${PUBKEY}" != ed25519:* ]]; then
  echo "pubkey must start with 'ed25519:'" >&2
  exit 1
fi
if [[ "${PQ_PUBKEY}" != mldsa:* ]]; then
  echo "pq_pubkey must start with 'mldsa:'" >&2
  exit 1
fi

sed -i.bak -E "s|id: REPLACE_ME_CLIENT_ID|id: ${CLID}|" server.yaml
sed -i.bak -E "s|pubkey: ed25519:REPLACE_ME_CLIENT_PUBKEY|pubkey: ${PUBKEY}|" server.yaml
sed -i.bak -E "s|pq_pubkey: mldsa:REPLACE_ME_CLIENT_PQ_PUBKEY|pq_pubkey: ${PQ_PUBKEY}|" server.yaml
rm -f server.yaml.bak

echo "==> server.yaml patched. start with: docker compose up -d"
