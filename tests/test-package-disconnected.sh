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
package="$tmp/extract/$name"
for path in docs/OSCAP-SOURCE.md docs/CISCO-CONFIG.md docs/snapshots/oscap_scan.yml docs/snapshots/run-lab-oscap.sh scripts/preflight-offline.sh schemas/SV3_CKLB_1_0_JSON_SCHEMA.json schemas/PROVENANCE.md; do
  [[ -f $package/$path && -r $package/$path ]] || { echo "missing packaged source: $path" >&2; exit 1; }
  cmp "$repo/$path" "$package/$path"
  (cd "$package" && grep -Fqx "$(sha256sum "$path")" SHA256SUMS) || {
    echo "missing inner checksum: $path" >&2; exit 1;
  }
done
printf '%s  %s\n' '8b88205de07662006e1660b1decad677d344828d6687b1dd26bca15105b7bb37' "$repo/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json" | sha256sum -c -
[[ $(stat -c %a "$package/docs/snapshots/oscap_scan.yml") == 644 && $(stat -c %a "$package/docs/snapshots/run-lab-oscap.sh") == 644 ]] || { echo 'snapshot mode is not nonexecutable 0644' >&2; exit 1; }
[[ $(stat -c %a "$package/scripts/preflight-offline.sh") == 755 ]] || { echo 'preflight is not executable 0755' >&2; exit 1; }
# These relative links must resolve inside the extracted bundle, not back to the repo.
assert_relative_link() {
  local source=$1 link=$2 target
  grep -Fq "]($link)" "$package/$source" || { echo "missing relative link: $source -> $link" >&2; exit 1; }
  target=${link%%#*}
  [[ -r "$package/$(dirname "$source")/$target" ]] || { echo "broken relative link: $source -> $link" >&2; exit 1; }
}
assert_relative_link README.md docs/OSCAP-SOURCE.md
assert_relative_link docs/OSCAP-SOURCE.md snapshots/oscap_scan.yml
assert_relative_link docs/OSCAP-SOURCE.md snapshots/run-lab-oscap.sh
assert_relative_link docs/OSCAP-SOURCE.md BATCH-CKLB.md#pairing-and-output
for major in 7 8 9 10; do
  cmp "$repo/templates/RHEL_${major}_STIG.tailoring.yaml" "$tmp/extract/$name/templates/RHEL_${major}_STIG.tailoring.yaml"
done
env -u GOPATH -u GOROOT GOPROXY=off GOSUMDB=off "$tmp/extract/$name/bin/stig-evidence" batch-cklb --help >/dev/null
env -u GOPATH -u GOROOT GOPROXY=off GOSUMDB=off "$tmp/extract/$name/bin/stig-evidence" cisco-cklb --help >/dev/null
[[ $(file -b "$tmp/extract/$name/bin/stig-evidence") == *'statically linked'* ]]
if "$repo/scripts/package-disconnected.sh" '../unsafe' "$tmp" >/dev/null 2>&1; then
  echo 'unsafe release name accepted' >&2
  exit 1
fi
echo 'PASS: offline release archive, checksums, scan-source docs and snapshot, relative links, four templates, static executable and invalid-name rejection'
