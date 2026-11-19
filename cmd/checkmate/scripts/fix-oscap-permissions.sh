#!/usr/bin/env bash
# Make an owner-controlled OpenSCAP results tree suitable for docket.
set -euo pipefail
umask 077
usage() {
  printf 'Usage: %s [--apply] ABSOLUTE_OSCAP_RESULTS_DIR\n' "${0##*/}" >&2
  printf 'Default is a read-only preview. --apply sets directories 0700 and regular files 0600.\n' >&2
  exit 2
}
die() { printf 'fix-oscap-permissions: %s\n' "$*" >&2; exit 1; }
apply=0
if [[ ${1:-} == --apply ]]; then apply=1; shift; fi
[[ $# == 1 && "$1" == /* ]] || usage
root=$1
[[ -d "$root" && ! -L "$root" ]] || die 'root must be an existing directory, not a symlink'
canonical=$(realpath -e -- "$root") || die 'cannot resolve results root'
[[ "$root" == "$canonical" ]] || die 'use a canonical absolute path without symlink components'
[[ "$root" != / && "$root" != "$HOME" ]] || die 'refusing filesystem root or home directory'
manifest=$(mktemp "${TMPDIR:-$HOME}/checkmate-oscap-paths.XXXXXXXX") || die 'cannot create private path manifest'
trap 'rm -f -- "$manifest"' EXIT
# Build and validate the entire manifest before changing any mode. No symlink
# is followed; any symlink, special file, or other owner aborts the operation.
find -P "$root" -print0 > "$manifest" || die 'cannot traverse the complete results tree'
mapfile -d '' -t entries < "$manifest"
((${#entries[@]})) || die 'empty results tree'
dirs=0
files=0
results=0
for path in "${entries[@]}"; do
  [[ ! -L "$path" ]] || die "symlink found: $path"
  if [[ -d "$path" ]]; then
    ((dirs+=1))
  elif [[ -f "$path" ]]; then
    [[ $(stat -c %h -- "$path") == 1 ]] || die "hard-linked file found (could change modes outside root): $path"
    ((files+=1))
    case "$path" in
      *.results.xml|*.results.xccdf.xml|*_XCCDF_Results.xml) ((results+=1));;
    esac
  else
    die "not a regular file or directory: $path"
  fi
  [[ $(stat -c %u -- "$path") == "$EUID" ]] || die "not owned by current user: $path"
done
((results)) || die 'no recognizable OpenSCAP XCCDF results found under root'
printf '%s: %d directories -> 0700; %d regular files -> 0600; %d XCCDF results.\n' "$root" "$dirs" "$files" "$results"
if (( ! apply )); then
  printf 'Preview only. Re-run with --apply before the absolute path to change permissions.\n'
  exit 0
fi
# find emits directories before their descendants. Restrict each directory
# first; no path outside the validated tree is intentionally changed.
for path in "${entries[@]}"; do
  if [[ -d "$path" && ! -L "$path" ]]; then
    chmod 700 -- "$path"
  elif [[ -f "$path" && ! -L "$path" ]]; then
    chmod 600 -- "$path"
  else
    die "tree changed during apply; stopped at: $path"
  fi
done
printf 'Applied owner-private modes. Ownership and file contents were not changed.\n'
