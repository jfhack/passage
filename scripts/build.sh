#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(grep -E '^const version = "' cmd/passage/main.go \
            | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ -z "${VERSION}" ]]; then
  echo "could not read version from cmd/passage/main.go" >&2
  exit 1
fi

LDFLAGS="-s -w -X main.version=${VERSION}"
COMMON_FLAGS=(-trimpath -buildvcs=false -ldflags "${LDFLAGS}")

mkdir -p dist

build_one() {
  local goos="$1" goarch="$2"
  local outname="passage"
  if [[ "${goos}" == "windows" ]]; then outname="passage.exe"; fi
  local stage="dist/.stage-${goos}-${goarch}"
  mkdir -p "${stage}"
  echo "==> building ${goos}/${goarch}"
  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build "${COMMON_FLAGS[@]}" -o "${stage}/${outname}" ./cmd/passage
  cp LICENSE "${stage}/"
  sed '/<p align="center">/,/<\/p>/d' README.md > "${stage}/README.md"
  cp -r examples "${stage}/examples"
  local archive="dist/passage-${VERSION}-${goos}-${goarch}.tar.gz"
  tar -C "${stage}" -czf "${archive}" .
  rm -rf "${stage}"
  echo "    -> ${archive}"
}

if [[ "${1:-}" == "all" ]]; then
  for combo in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
    build_one "${combo%/*}" "${combo#*/}"
  done
  echo "done. version=${VERSION}"
  exit 0
fi

OUT="dist/passage"
if [[ "${GOOS:-$(go env GOOS)}" == "windows" ]]; then OUT="dist/passage.exe"; fi
echo "==> building host (${VERSION})"
CGO_ENABLED=0 go build "${COMMON_FLAGS[@]}" -o "${OUT}" ./cmd/passage
echo "    -> ${OUT}"
