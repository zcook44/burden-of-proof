#!/usr/bin/env bash
# Build the Ceasefire Linux/amd64 archive from this repository's vendor tree.
# The archive installs the docket and checkmate commands. Those names do not change.
set -euo pipefail
umask 077

usage() {
  printf 'Usage: %s VERSION OUTPUT_DIRECTORY\n' "$0" >&2
  printf 'Example: %s 2.1.0 ./dist/releases\n' "$0" >&2
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
# shellcheck source=ceasefire-require-go.sh
source "$root/scripts/ceasefire-require-go.sh"
ceasefire_require_go
# Fail instead of fetching a compiler or dependency in a disconnected build.
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
export GOOS=linux GOARCH=amd64 GOFLAGS=-mod=vendor
(cd "$root" && go test ./...)
install -d -m 700 "$output"
output=$(cd -- "$output" && pwd -P)
[[ $(stat -c %u "$output") -eq $(id -u) && $(stat -c %a "$output") == 700 ]] || {
  echo "Output directory must be owned by this user and mode 0700: $output" >&2; exit 1;
}
name="ceasefire-${version}-linux-amd64"
[[ ! -e $output/$name.tar.gz && ! -e $output/$name.tar.gz.sha256 ]] || {
  echo "Refusing to overwrite an existing release: $name" >&2; exit 1;
}
stage=$(mktemp -d "$output/.package.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
package="$stage/$name"
install -d -m 700 "$package" "$package/bin" "$package/scripts" "$package/templates" "$package/cisco-library" "$package/docs" "$package/docs/snapshots" "$package/contracts" "$package/schemas"
(cd "$root" && go build -trimpath -ldflags='-s -w' -o "$package/bin/docket" ./cmd/docket)
(cd "$root" && go build -trimpath -ldflags='-s -w' -o "$package/bin/checkmate" ./cmd/checkmate)
install -m 755 "$root/scripts/ceasefire-preflight.sh" "$package/scripts/ceasefire-preflight.sh"
install -m 755 "$root/scripts/install-ceasefire.sh" "$package/scripts/install-ceasefire.sh"
install -m 644 "$root/scripts/ceasefire-require-go.sh" "$package/scripts/ceasefire-require-go.sh"
install -m 644 "$root/scripts/docket-completion.bash" "$package/scripts/docket-completion.bash"
install -m 644 "$root/scripts/checkmate-completion.bash" "$package/scripts/checkmate-completion.bash"
install -m 755 "$root/scripts/generate-cisco-tailoring.py" "$package/scripts/generate-cisco-tailoring.py"
install -m 755 "$root/scripts/generate-cisco-examples.py" "$package/scripts/generate-cisco-examples.py"
install -m 755 "$root/cmd/checkmate/scripts/unpack-stig-library.sh" "$package/scripts/unpack-stig-library.sh"
install -m 755 "$root/cmd/checkmate/scripts/fix-oscap-permissions.sh" "$package/scripts/fix-oscap-permissions.sh"
install -m 755 "$root/cmd/checkmate/scripts/stage-offline-examples.py" "$package/scripts/stage-offline-examples.py"
install -m 644 "$root/go.mod" "$root/go.sum" "$package/"
if [[ -L $root/vendor || ! -f $root/vendor/modules.txt ]]; then
  echo 'vendor/modules.txt is missing. Refusing to build without the vendored modules.' >&2
  exit 1
fi
cp -a "$root/vendor" "$package/vendor"
if find "$package/vendor" -type l -print -quit | grep -q .; then
  echo 'vendor tree contains a symlink' >&2
  exit 1
fi
install -m 644 "$root/README.md" "$package/README.md"
install -m 644 "$root/LICENSE" "$package/LICENSE"
install -m 644 "$root/contracts/asset-record-v1.md" "$package/contracts/asset-record-v1.md"
for doc in README BATCH-CKLB CISCO-CONFIG GO-MIGRATION WORKFLOW DISCONNECTED-RELEASE OSCAP-SOURCE NETWORK-SCAN NETWORK-ADMIN-WALKTHROUGH CISCO-SCAN-PROCESS RHEL-OSCAP-WORKFLOW TAILORING QUARTERLY-RUNBOOK CONFIG; do
  install -m 644 "$root/docs/$doc.md" "$package/docs/$doc.md"
done
install -m 644 "$root/docs/snapshots/oscap_scan.yml" "$package/docs/snapshots/oscap_scan.yml"
install -m 644 "$root/docs/snapshots/run-lab-oscap.sh" "$package/docs/snapshots/run-lab-oscap.sh"
install -m 644 "$root/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json" "$root/schemas/PROVENANCE.md" "$package/schemas/"
for major in 7 8 9 10; do
  install -m 644 "$root/templates/RHEL_${major}_STIG.tailoring.yaml" "$package/templates/RHEL_${major}_STIG.tailoring.yaml"
done
# Include Cisco root-layer tailoring files (schema v3, partial)
for cisco_file in "$root"/stig-library-cisco/*.tailoring.yaml; do
  [[ -f $cisco_file && ! -L $cisco_file ]] && install -m 644 "$cisco_file" "$package/cisco-library/$(basename "$cisco_file")"
done
commit=$(git -C "$root" rev-parse --verify HEAD 2>/dev/null || printf 'unversioned')
source_state=unknown
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  source_state=clean
  [[ -z $(git -C "$root" status --porcelain --untracked-files=normal) ]] || source_state=dirty
fi
{
  printf 'Product: Ceasefire\nVersion: %s\nTarget: linux/amd64 (CGO_ENABLED=0)\n' "$version"
  printf 'Commands: docket, checkmate\n'
  printf 'Go: %s\nSource commit: %s\nSource worktree: %s\n' "$(go version)" "$commit" "$source_state"
  printf 'Build: GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor\n'
  printf 'Contents: Ceasefire archive with the docket and checkmate commands, Ceasefire installer, preflight, Go check, completions, Cisco tailoring and example generators, STIG library and permission helpers, vendored Go modules, RHEL templates (4), Cisco partial root tailoring (25), DISA CKLB schema, documentation and file checksums.\n'
  printf 'Not included: official DISA benchmarks, SSG scan inputs, Cisco running configs, device collectors, private evidence, credentials, signatures.\n'
} > "$package/RELEASE.txt"
(
  cd "$package"
  list=$(mktemp)
  find . -type f -printf '%P\n' | LC_ALL=C sort > "$list"
  while IFS= read -r file; do
    sha256sum "$file"
  done < "$list" > SHA256SUMS
  rm -f "$list"
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
