#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-0.4.0}"
./scripts/package.sh "$version"
test -x release/checkmate
test -f "release/checkmate_${version}_linux_amd64.tar.gz"
test -f "release/checkmate_${version}_linux_arm64.tar.gz"
(cd release && sha256sum -c SHA256SUMS)
git check-ignore -q release/checkmate
if git check-ignore -q "release/checkmate_${version}_linux_amd64.tar.gz"; then
  echo "versioned release archives must remain trackable" >&2
  exit 1
fi
for arch in amd64 arm64; do
  archive="release/checkmate_${version}_linux_${arch}.tar.gz"
  prefix="checkmate_${version}_linux_${arch}"
  cmp README.md <(tar -xOzf "$archive" "$prefix/README.md")
  cmp docs/OFFLINE-EXAMPLES.md <(tar -xOzf "$archive" "$prefix/docs/OFFLINE-EXAMPLES.md")
  cmp schemas/SV3_CKLB_1_0_JSON_SCHEMA.json <(tar -xOzf "$archive" "$prefix/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json")
  cmp schemas/PROVENANCE.md <(tar -xOzf "$archive" "$prefix/schemas/PROVENANCE.md")
  diff -u <(printf '%s\n' "$prefix/" "$prefix/checkmate" "$prefix/README.md" "$prefix/docs/" "$prefix/docs/OFFLINE-EXAMPLES.md" "$prefix/schemas/" "$prefix/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json" "$prefix/schemas/PROVENANCE.md" "$prefix/scripts/" "$prefix/scripts/install-checkmate.sh" "$prefix/scripts/checkmate-completion.bash" | sort) \
    <(tar -tzf "$archive" | sort)
done
printf '%s  %s\n' '8b88205de07662006e1660b1decad677d344828d6687b1dd26bca15105b7bb37' schemas/SV3_CKLB_1_0_JSON_SCHEMA.json | sha256sum -c -
fixture=$(mktemp -d "${TMPDIR:-/home/zrc/.hermes/cache/scratch}/checkmate-release-test.XXXXXX")
trap 'rm -r "$fixture"' EXIT
mkdir -m 700 "$fixture/checklists"
printf '%s\n' '{"title":"fixture.cklb","id":"123e4567-e89b-12d3-a456-426614174000","stigs":[{"stig_name":"Cisco IOS STIG","display_name":"Cisco IOS","stig_id":"Cisco_IOS_STIG","release_info":"V1R2","uuid":"123e4567-e89b-12d3-a456-426614174001","size":1,"rules":[{"group_id":"V-42","rule_id":"SV-42r1_rule","rule_title":"Login policy","severity":"high","status":"open","comments":"","finding_details":""}]}]}' > "$fixture/checklists/sample.cklb"
printf '%s\n' '{"$schema":"https://json-schema.org/draft/2019-09/schema","type":"object","required":["title"],"properties":{"title":{"type":"string"}}}' > "$fixture/schema.json"
release/checkmate --root "$fixture/checklists" --list | grep -q 'Cisco_IOS_STIG  V-42'
release/checkmate --root "$fixture/checklists" --export-tailoring "$fixture/tailoring" | grep -q 'Exported 1 rules'
grep -q 'rule_name: PLACEHOLDER' "$fixture/tailoring/Cisco_IOS_STIG.tailoring.yaml"
grep -q 'stig_id: V-42' "$fixture/tailoring/Cisco_IOS_STIG.tailoring.yaml"
grep -q 'status: open' "$fixture/tailoring/Cisco_IOS_STIG.tailoring.yaml"
if release/checkmate --root "$fixture/checklists" --export-tailoring "$fixture/tailoring" >/dev/null 2>&1; then
  echo 'export unexpectedly overwrote an existing tailoring file' >&2
  exit 1
fi
if release/checkmate --root "$fixture/checklists" --validate >/dev/null 2>&1; then echo '--validate unexpectedly accepted no schema' >&2; exit 1; fi
release/checkmate --root "$fixture/checklists" --validate --schema "$fixture/schema.json" | grep -q 'Validated 1 checklist(s) against supplied schema'
# The official schema rejects an unknown top-level field that CKLB parsing tolerates.
python3 - "$fixture/checklists/sample.cklb" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
doc = json.loads(p.read_text())
doc['unexpected_schema_test_field'] = True
p.write_text(json.dumps(doc))
PY
if release/checkmate --root "$fixture/checklists" --validate --schema schemas/SV3_CKLB_1_0_JSON_SCHEMA.json >/dev/null 2>&1; then echo 'unknown CKLB field passed DISA schema' >&2; exit 1; fi
echo "Release directory verified"
