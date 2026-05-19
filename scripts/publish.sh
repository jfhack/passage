#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-ghcr.io/jfhack/passage}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64,linux/arm/v7}"
BUILDER="${BUILDER:-passage-builder}"

VERSION=$(grep -E 'const version = "[^"]+"' cmd/passage/main.go | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "${VERSION}" ]; then
    echo "publish: could not extract version from cmd/passage/main.go" >&2
    exit 1
fi

echo "publish: ${IMAGE}:${VERSION} + ${IMAGE}:latest (${PLATFORMS})"

if ! docker buildx inspect "${BUILDER}" >/dev/null 2>&1; then
    echo "publish: creating buildx builder '${BUILDER}'"
    docker buildx create --name "${BUILDER}" --driver docker-container --bootstrap
fi

docker buildx build \
    --builder "${BUILDER}" \
    --platform "${PLATFORMS}" \
    --tag "${IMAGE}:${VERSION}" \
    --tag "${IMAGE}:latest" \
    --push \
    .

echo "publish: pushed ${IMAGE}:${VERSION} and ${IMAGE}:latest"

docker buildx rm "${BUILDER}"
echo "publish: removed builder '${BUILDER}'"
