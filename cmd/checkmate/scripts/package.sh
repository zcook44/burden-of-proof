#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:?usage: scripts/package.sh VERSION}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'version must be X.Y.Z' >&2; exit 2; }
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=vendor
printf '%s  %s\n' '8b88205de07662006e1660b1decad677d344828d6687b1dd26bca15105b7bb37' schemas/SV3_CKLB_1_0_JSON_SCHEMA.json | sha256sum -c -
mkdir -p release
go test -mod=vendor ./...
: > release/SHA256SUMS
for arch in amd64 arm64; do
  name="checkmate_${version}_linux_${arch}"
  mkdir -p "release/$name"
  GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "release/$name/checkmate" .
  cp README.md "release/$name/README.md"
  mkdir -p "release/$name/docs"
  cp docs/OFFLINE-EXAMPLES.md "release/$name/docs/OFFLINE-EXAMPLES.md"
  mkdir -p "release/$name/schemas" "release/$name/scripts"
  cp schemas/SV3_CKLB_1_0_JSON_SCHEMA.json schemas/PROVENANCE.md "release/$name/schemas/"
  cp scripts/install-checkmate.sh scripts/checkmate-completion.bash "release/$name/scripts/"
  chmod 755 "release/$name/scripts/install-checkmate.sh"
  chmod 644 "release/$name/scripts/checkmate-completion.bash"
  if [[ "$arch" == amd64 ]]; then
    direct_tmp=$(mktemp release/.checkmate.XXXXXX)
    cp "release/$name/checkmate" "$direct_tmp"
    chmod 755 "$direct_tmp"
    mv -f "$direct_tmp" release/checkmate
  fi
  tar -C release -czf "release/$name.tar.gz" "$name"
  (cd release && sha256sum "$name.tar.gz") >> release/SHA256SUMS
  rm -r "release/$name"
done
(cd release && sha256sum checkmate) >> release/SHA256SUMS
(cd release && sha256sum -c SHA256SUMS)
