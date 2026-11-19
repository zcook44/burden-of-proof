#!/usr/bin/env bash
# Read-only offline readiness check for a private scan tree and optional CKLBs.
set -euo pipefail
umask 077
usage() {
  printf 'Usage: %s --converter BIN --input-root DIR --library-root DIR [--evidence-root DIR] [--checkmate BIN --checklist-root DIR [--schema JSON]]\n' "${0##*/}" >&2
  exit 2
}
die() { printf 'preflight-offline: %s\n' "$*" >&2; exit 1; }
converter='' input='' library='' evidence='' checkmate='' checklist='' schema=''
while (($#)); do
  (($# >= 2)) || usage
  case $1 in
    --converter) converter=$2 ;;
    --input-root) input=$2 ;;
    --library-root) library=$2 ;;
    --evidence-root) evidence=$2 ;;
    --checkmate) checkmate=$2 ;;
    --checklist-root) checklist=$2 ;;
    --schema) schema=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[[ -n $converter && -n $input && -n $library ]] || usage
[[ ( -z $checkmate && -z $checklist && -z $schema ) || ( -n $checkmate && -n $checklist ) ]] || usage
for binary in "$converter" ${checkmate:+"$checkmate"}; do
  [[ -f $binary && ! -L $binary && -x $binary ]] || die "not an executable regular binary: $binary"
done
if [[ -n $schema ]]; then
  [[ -f $schema && ! -L $schema && -r $schema ]] || die "schema must be a readable regular file: $schema"
fi
workdir=$(mktemp -d "${TMPDIR:-$HOME}/preflight.XXXXXXXX") || die 'cannot create private workspace'
trap 'rm -rf -- "$workdir"' EXIT
manifest=$workdir/paths
inventory=$workdir/inventory
check_tree() {
  local root=$1 path uid mode count=0
  [[ $root == /* && -d $root && ! -L $root && $(realpath -e -- "$root") == "$root" ]] || die "tree must be a canonical absolute non-symlink directory: $root"
  find -P "$root" -print0 > "$manifest" || die "cannot traverse $root"
  local -a paths=()
  mapfile -d '' -t paths < "$manifest"
  ((${#paths[@]})) || die "empty tree: $root"
  for path in "${paths[@]}"; do
    [[ ! -L $path ]] || die "symlink in tree: $path"
    [[ -d $path || -f $path ]] || die "special file in tree: $path"
    uid=$(stat -c %u -- "$path")
    mode=$(stat -c %a -- "$path")
    [[ $uid == "$EUID" ]] || die "not owned by current user: $path"
    base=${path##*/}
    if [[ -f $path && $base == *_Manual-xccdf.xml ]]; then
      # Public DISA manuals may be mode 0644. They must not be writable by
      # group or other, and they must not be executable.
      (( (8#$mode & 0133) == 0 )) || die "benchmark must not be group/world-writable or executable: $path (mode $mode)"
    else
      (( (8#$mode & 0077) == 0 )) || die "not owner-private: $path (mode $mode)"
    fi
    ((count+=1))
  done
  printf 'TREE OK: %s (%d entries)\n' "$root" "$count"
  if [[ -f $root/SHA256SUMS ]]; then
    (cd -- "$root" && sha256sum -c SHA256SUMS >/dev/null) || die "checksum verification failed: $root/SHA256SUMS"
    printf 'CHECKSUMS OK: %s/SHA256SUMS\n' "$root"
  else
    printf 'CHECKSUMS SKIPPED (no SHA256SUMS): %s\n' "$root"
  fi
}
check_tree "$input"
check_tree "$library"
if [[ -n $checklist && $checklist != "$input" && $checklist != "$library" ]]; then check_tree "$checklist"; fi
if [[ -n $evidence && $evidence != "$input" && $evidence != "$library" ]]; then check_tree "$evidence"; fi

# Every tailoring file the converters will read, plus files they would skip.
# A non-zero tailoring check stops the preflight. Nested host files are not applied.
printf 'TAILORING VALIDATION:\n'
if ! "$converter" tailoring check --library-root "$library" --scan-root "$input"; then
  die "tailoring validation failed"
fi
if [[ -n $evidence && $evidence != "$input" ]]; then
  if ! "$converter" tailoring check --library-root "$library" --scan-root "$evidence"; then
    die "tailoring validation failed for evidence root"
  fi
fi
printf 'Tailoring files validated.\n'

misplaced=0
while IFS= read -r -d '' path; do
  relative=${path#"$input"/}
  if [[ $relative == "$path" ]]; then
    continue
  fi
  depth=$(printf '%s' "$relative" | tr -cd '/' | wc -c)
  if ((depth > 1)); then
    printf 'preflight-offline: nested tailoring file is not loaded from a host directory: %s\n' "$path" >&2
    misplaced=$((misplaced + 1))
  fi
done < <(find "$input" -name '*.tailoring.yaml' -type f -print0 2>/dev/null || true)
if ((misplaced > 0)); then
  die "$misplaced tailoring file(s) are nested deeper than the host directory"
fi

printf 'CONVERTER DRY RUN (no files written):\n'
"$converter" batch-cklb --input-root "$input" --library-root "$library" --dry-run
if [[ -n $checkmate ]]; then
  "$checkmate" --root "$checklist" --list > "$inventory"
  printf 'CHECKMATE INVENTORY OK: %s (%s output lines)\n' "$checklist" "$(wc -l < "$inventory")"
  if [[ -n $schema ]]; then
    "$checkmate" --root "$checklist" --validate --schema "$schema"
  fi
fi
printf 'Preflight complete. No scans, conversions, checklist edits, or guest changes were requested.\n'
