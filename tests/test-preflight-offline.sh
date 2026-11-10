#!/usr/bin/env bash
set -euo pipefail
tmp=$(mktemp -d "${TMPDIR:?}/preflight-offline-test.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
mkdir -m 700 "$tmp/input" "$tmp/library" "$tmp/checklists"
printf 'scan\n' > "$tmp/input/one.results.xml"
printf 'benchmark\n' > "$tmp/library/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml"
printf '{}\n' > "$tmp/checklists/a.cklb"
chmod 600 "$tmp/input/one.results.xml" "$tmp/library"/*.xml "$tmp/checklists/a.cklb"
(cd "$tmp/input" && sha256sum one.results.xml > SHA256SUMS && chmod 600 SHA256SUMS)
(cd "$tmp/library" && sha256sum *.xml > SHA256SUMS && chmod 600 SHA256SUMS)
cat > "$tmp/converter" <<'SH'
#!/usr/bin/env bash
printf 'converter %s\n' "$*" >> "$TEST_LOG"
[[ $* == *'--dry-run'* ]] || exit 1
printf 'bundles: 1; no files written\n'
SH
cat > "$tmp/checkmate" <<'SH'
#!/usr/bin/env bash
printf 'checkmate %s\n' "$*" >> "$TEST_LOG"
case $* in
  *--list*) printf 'RHEL_9_STIG V-1\n' ;;
  *--validate*) printf 'Validated 1 checklist(s)\n' ;;
  *) exit 1 ;;
esac
SH
chmod 700 "$tmp/converter" "$tmp/checkmate"
script=/home/zrc/git/burden-of-proof/scripts/preflight-offline.sh
export TEST_LOG="$tmp/log"
"$script" --converter "$tmp/converter" --input-root "$tmp/input" --library-root "$tmp/library" --checkmate "$tmp/checkmate" --checklist-root "$tmp/checklists" > "$tmp/out"
grep -q 'bundles: 1; no files written' "$tmp/out"
grep -q 'converter .*--dry-run' "$TEST_LOG"
grep -q 'checkmate .*--list' "$TEST_LOG"
# Optional schema validation and converter-only mode make no edit.
printf '{}\n' > "$tmp/schema.json"; chmod 600 "$tmp/schema.json"
: > "$TEST_LOG"
"$script" --converter "$tmp/converter" --input-root "$tmp/input" --library-root "$tmp/library" --checkmate "$tmp/checkmate" --checklist-root "$tmp/checklists" --schema "$tmp/schema.json" > "$tmp/out"
grep -q 'checkmate .*--validate --schema' "$TEST_LOG"
: > "$TEST_LOG"
"$script" --converter "$tmp/converter" --input-root "$tmp/input" --library-root "$tmp/library" > "$tmp/out"
! grep -q '^checkmate ' "$TEST_LOG"
# Any symlink in a source tree is rejected before either CLI runs.
ln -s /etc/passwd "$tmp/input/escape"
: > "$TEST_LOG"
if "$script" --converter "$tmp/converter" --input-root "$tmp/input" --library-root "$tmp/library" > "$tmp/out" 2>&1; then
  echo 'accepted symlink in scan tree' >&2; exit 1
fi
[[ ! -s $TEST_LOG ]] || { echo 'called tools after symlink check failure' >&2; exit 1; }
rm "$tmp/input/escape"
# Checksum failure must stop before either tool is invoked.
printf 'changed\n' > "$tmp/input/one.results.xml"
: > "$TEST_LOG"
if "$script" --converter "$tmp/converter" --input-root "$tmp/input" --library-root "$tmp/library" --checkmate "$tmp/checkmate" --checklist-root "$tmp/checklists" > "$tmp/out" 2>&1; then
  echo 'accepted altered scan despite manifest' >&2; exit 1
fi
[[ ! -s $TEST_LOG ]] || { echo 'called tools after checksum failure' >&2; exit 1; }
echo 'PASS: offline preflight is read-only and fails before tools on bad inputs'
