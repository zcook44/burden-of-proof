#!/usr/bin/env bash
# Extract RHEL and Cisco manual XCCDF benchmarks into a flat private library.
set -euo pipefail
umask 077
usage() {
  printf 'Usage: %s SOURCE_ZIP_OR_DIR DEST_LIBRARY_DIR\n' "${0##*/}" >&2
  printf 'DEST must not exist; SOURCE_DIR contains ZIP files directly (not recursively).\n' >&2
  exit 2
}
die() { printf 'unpack-stig-library: %s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || usage
source=$1
dest=$2
[[ -e "$source" && ! -L "$source" ]] || die 'source must exist and must not be a symlink'
[[ -f "$source" || -d "$source" ]] || die 'source must be a regular ZIP or a directory of ZIPs'
parent=$(realpath -e -- "$(dirname -- "$dest")") || die 'destination parent does not exist'
base=$(basename -- "$dest")
[[ "$base" != . && "$base" != .. && "$dest" != */. && "$dest" != */.. ]] || die 'invalid destination name'
dest="$parent/$base"
[[ ! -e "$dest" && ! -L "$dest" ]] || die "destination already exists: $dest"
[[ -d "$parent" && ! -L "$parent" ]] || die 'destination parent must be an ordinary directory'
[[ $(stat -c %u -- "$parent") == "$EUID" ]] || die 'destination parent must be owned by the current user'
parent_mode=$(stat -c %a -- "$parent")
(( (8#$parent_mode & 0022) == 0 )) || die 'destination parent must not be group/world writable'
archives=()
if [[ -f "$source" ]]; then
  [[ "$source" == *.zip ]] || die 'source must be a .zip file'
  archives=("$source")
else
  shopt -s nullglob
  archives=("$source"/*.zip)
  shopt -u nullglob
  ((${#archives[@]})) || die 'source directory contains no .zip files'
fi
stage=$(mktemp -d -- "$parent/.checkmate-stig-library.XXXXXXXX") || die 'cannot create private staging directory'
trap 'rm -rf -- "$stage"' EXIT
list="$stage/.entries"
count=0
for archive in "${archives[@]}"; do
  [[ -f "$archive" && ! -L "$archive" ]] || die "not a regular, non-symlink archive: $archive"
  unzip -Z -1 -- "$archive" > "$list" || die "cannot list ZIP: $archive"
  while IFS= read -r entry; do
    # Allowlisted manual XCCDF XML is streamed, never unpacked by archive path.
    # Cisco archives use both STIG_VxRy_Manual and VxRy_STIG_Manual ordering.
    [[ "$entry" =~ (^|/)(U_RHEL_[0-9]+_STIG_V[0-9]+R[0-9]+_Manual-xccdf\.xml|U_Cisco_[A-Za-z0-9_-]*STIG_V[0-9]+R[0-9]+_Manual-xccdf\.xml|U_Cisco_[A-Za-z0-9_-]*V[0-9]+R[0-9]+_STIG_Manual-xccdf\.xml)$ ]] || continue
    [[ "$entry" =~ ^[A-Za-z0-9._/-]+$ && "$entry" != ../* && "$entry" != */../* && "$entry" != */.. ]] || die "unsafe archive member: $entry"
    name=${entry##*/}
    [[ ! -e "$stage/$name" ]] || die "duplicate benchmark filename: $name"
    unzip -p -- "$archive" "$entry" > "$stage/$name" || die "could not extract $entry from $archive"
    chmod 600 -- "$stage/$name"
    ((count+=1))
  done < "$list"
done
rm -- "$list"
((count)) || die 'no RHEL or Cisco manual XCCDF XML found in source ZIP(s)'
[[ ! -e "$dest" && ! -L "$dest" ]] || die "destination appeared during extraction: $dest"
mv -T -- "$stage" "$dest" || die "cannot promote library: $dest"
trap - EXIT
printf 'Extracted %d RHEL/Cisco manual XCCDF benchmark(s) into %s (0700 directory, 0600 XML).\n' "$count" "$dest"
printf 'Optional RHEL_N_STIG.tailoring.yaml policies must be supplied separately with mode 0600.\n'
