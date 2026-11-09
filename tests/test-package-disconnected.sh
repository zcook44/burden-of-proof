#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
tmp=$(mktemp -d "${TMPDIR:?}/stig-evidence-package-test.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
version=offline-smoke
"$repo/scripts/package-disconnected.sh" "$version" "$tmp"
name="stig-evidence-${version}-linux-amd64"
archive="$tmp/$name.tar.gz"
[[ -s $archive && -s $archive.sha256 ]]
(cd "$tmp" && sha256sum -c "$name.tar.gz.sha256")
tar -tzf "$archive" | while IFS= read -r entry; do
  [[ $entry == "$name/"* || $entry == "$name/" ]] || { echo "unexpected archive entry: $entry" >&2; exit 1; }
done
mkdir -m 700 "$tmp/extract"
tar -xzf "$archive" -C "$tmp/extract"
(cd "$tmp/extract/$name" && sha256sum -c SHA256SUMS)
for major in 7 8 9 10; do
  cmp "$repo/templates/RHEL_${major}_STIG.tailoring.yaml" "$tmp/extract/$name/templates/RHEL_${major}_STIG.tailoring.yaml"
done
env -u GOPATH -u GOROOT GOPROXY=off GOSUMDB=off "$tmp/extract/$name/bin/stig-evidence" batch-cklb --help >/dev/null
[[ $(file -b "$tmp/extract/$name/bin/stig-evidence") == *'statically linked'* ]]
if "$repo/scripts/package-disconnected.sh" '../unsafe' "$tmp" >/dev/null 2>&1; then
  echo 'unsafe release name accepted' >&2
  exit 1
fi
echo 'PASS: offline release archive, checksums, four templates, static executable and invalid-name rejection'
