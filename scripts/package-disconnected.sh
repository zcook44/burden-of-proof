#!/usr/bin/env bash
# Build and package a Linux/amd64 runtime using only this repository's vendor tree.
set -euo pipefail
umask 077

usage() {
  printf 'Usage: %s VERSION OUTPUT_DIRECTORY\n' "$0" >&2
  printf 'Example: %s 1.0.0 ./dist/releases\n' "$0" >&2
  exit 2
}
[[ $# -eq 2 ]] || usage
version=$1
output=$2
[[ $version =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ && $version != *..* ]] || usage
[[ $output != '' && ! -L $output ]] || { echo 'Output directory must not be a symlink' >&2; exit 2; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
for required in go tar gzip sha256sum mktemp; do
  command -v "$required" >/dev/null || { echo "Missing required tool: $required" >&2; exit 1; }
done
for major in 7 8 9 10; do
  [[ -f $root/templates/RHEL_${major}_STIG.tailoring.yaml && ! -L $root/templates/RHEL_${major}_STIG.tailoring.yaml ]] || {
    echo "Missing or linked RHEL ${major} tailoring template" >&2; exit 1;
  }
done
[[ -f $root/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json && ! -L $root/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json ]] || {
  echo 'Missing or linked DISA CKLB schema' >&2; exit 1;
}
printf '%s  %s\n' '8b88205de07662006e1660b1decad677d344828d6687b1dd26bca15105b7bb37' "$root/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json" | sha256sum -c - >/dev/null
# Fail instead of fetching a compiler or dependency in a disconnected build.
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
export GOOS=linux GOARCH=amd64 GOFLAGS=-mod=vendor
(cd "$root" && go test ./...)
install -d -m 700 "$output"
output=$(cd -- "$output" && pwd -P)
[[ $(stat -c %u "$output") -eq $(id -u) && $(stat -c %a "$output") == 700 ]] || {
  echo "Output directory must be owned by this user and mode 0700: $output" >&2; exit 1;
}
name="stig-evidence-${version}-linux-amd64"
[[ ! -e $output/$name.tar.gz && ! -e $output/$name.tar.gz.sha256 ]] || {
  echo "Refusing to overwrite an existing release: $name" >&2; exit 1;
}
stage=$(mktemp -d "$output/.package.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
package="$stage/$name"
install -d -m 700 "$package" "$package/bin" "$package/scripts" "$package/templates" "$package/docs" "$package/docs/snapshots" "$package/contracts" "$package/schemas"
(cd "$root" && go build -trimpath -ldflags='-s -w' -o "$package/bin/stig-evidence" ./cmd/stig-evidence)
install -m 755 "$root/scripts/preflight-offline.sh" "$package/scripts/preflight-offline.sh"
install -m 644 "$root/README.md" "$package/README.md"
install -m 644 "$root/LICENSE" "$package/LICENSE"
install -m 644 "$root/contracts/asset-record-v1.md" "$package/contracts/asset-record-v1.md"
for doc in README BATCH-CKLB GO-MIGRATION WORKFLOW DISCONNECTED-RELEASE OSCAP-SOURCE; do
  install -m 644 "$root/docs/$doc.md" "$package/docs/$doc.md"
done
install -m 644 "$root/docs/snapshots/oscap_scan.yml" "$package/docs/snapshots/oscap_scan.yml"
install -m 644 "$root/docs/snapshots/run-lab-oscap.sh" "$package/docs/snapshots/run-lab-oscap.sh"
install -m 644 "$root/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json" "$root/schemas/PROVENANCE.md" "$package/schemas/"
for major in 7 8 9 10; do
  install -m 644 "$root/templates/RHEL_${major}_STIG.tailoring.yaml" "$package/templates/RHEL_${major}_STIG.tailoring.yaml"
done
commit=$(git -C "$root" rev-parse --verify HEAD 2>/dev/null || printf 'unversioned')
source_state=unknown
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  source_state=clean
  [[ -z $(git -C "$root" status --porcelain --untracked-files=normal) ]] || source_state=dirty
fi
{
  printf 'Product: stig-evidence\nVersion: %s\nTarget: linux/amd64 (CGO_ENABLED=0)\n' "$version"
  printf 'Go: %s\nSource commit: %s\nSource worktree: %s\n' "$(go version)" "$commit" "$source_state"
  printf 'Build: GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor\n'
  printf 'Contents: CLI, Bash read-only preflight, four per-OS YAML examples, DISA CKLB schema, documentation and file checksums.\n'
  printf 'Not included: official DISA benchmarks, SSG scan inputs, private evidence, credentials, signatures.\n'
} > "$package/RELEASE.txt"
(
  cd "$package"
  sha256sum bin/stig-evidence scripts/preflight-offline.sh README.md LICENSE RELEASE.txt \
    docs/*.md docs/snapshots/oscap_scan.yml docs/snapshots/run-lab-oscap.sh contracts/*.md templates/*.yaml schemas/*.json schemas/*.md > SHA256SUMS
)
source_date_epoch=${SOURCE_DATE_EPOCH:-0}
[[ $source_date_epoch =~ ^[0-9]+$ ]] || { echo 'SOURCE_DATE_EPOCH must be an unsigned integer' >&2; exit 2; }
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$stage" -cf - "$name" | gzip -n > "$stage/$name.tar.gz"
checksum=$(sha256sum "$stage/$name.tar.gz")
printf '%s  %s\n' "${checksum%% *}" "$name.tar.gz" > "$stage/$name.tar.gz.sha256"
# Same-filesystem hard links publish without replacing an earlier bundle.
ln "$stage/$name.tar.gz" "$output/$name.tar.gz"
ln "$stage/$name.tar.gz.sha256" "$output/$name.tar.gz.sha256"
printf 'PACKAGE %s\nCHECKSUM %s\n' "$output/$name.tar.gz" "$output/$name.tar.gz.sha256"
