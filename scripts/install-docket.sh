#!/usr/bin/env bash
# Unpack a built docket release and put the binary on PATH.
# --from-source builds from this checkout and fails if Go or the vendored
# modules are not actually usable offline.
set -euo pipefail
umask 022

usage() {
  printf 'Usage: %s [--prefix DIR] [TARBALL]\n' "${0##*/}" >&2
  printf '       %s --from-source [--prefix DIR]\n' "${0##*/}" >&2
  printf 'Default prefix is $HOME/.local. Default tarball is the newest dist/releases/docket-*-linux-amd64.tar.gz.\n' >&2
  exit 2
}
die() { printf 'install-docket: %s\n' "$*" >&2; exit 1; }

prefix=${HOME}/.local
from_source=0
tarball=
while (($#)); do
  case $1 in
    --from-source) from_source=1; shift ;;
    --prefix)
      [[ $# -ge 2 ]] || usage
      prefix=$2
      shift 2
      ;;
    -h|--help) usage ;;
    -*) die "unknown option: $1" ;;
    *) [[ -z $tarball ]] || usage; tarball=$1; shift ;;
  esac
done
[[ -n $prefix && $prefix != */ ]] || die "prefix must be a directory path"
[[ ! -L $prefix ]] || die "prefix must not be a symlink: $prefix"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd -- "$script_dir/.." && pwd -P)
completion_src=$script_dir/docket-completion.bash
extract_tmp=
trap '[[ -n ${extract_tmp:-} ]] && rm -rf -- "$extract_tmp"' EXIT

require_go() {
  [[ -f $script_dir/require-go.sh ]] || die "a source build needs this repository checkout, including scripts/require-go.sh and vendor/. The release archive does not include them. Installed docket and checkmate binaries do not need Go."
  # shellcheck source=require-go.sh
  source "$script_dir/require-go.sh"
  docket_require_go || die "source build needs Go 1.22 or newer. See the message above."
  [[ -f $repo/vendor/modules.txt && -d $repo/cmd/docket && -d $repo/cmd/checkmate ]] || die "vendor/, cmd/docket, or cmd/checkmate is missing. Refusing to download modules."
}

ensure_path() {
  local bindir=$1 line
  case :$PATH: in
    *:"$bindir":*) return 0 ;;
  esac
  line="export PATH=\"$bindir:\$PATH\""
  printf 'install-docket: %s is not on PATH.\n' "$bindir" >&2
  printf 'install-docket: add it for this account with:\n' >&2
  printf '  %s\n' "$line" >&2
}

binary=
checkmate_bin=
checkmate_completion=$script_dir/checkmate-completion.bash
if [[ $from_source -eq 1 ]]; then
  [[ -z $tarball ]] || die "--from-source does not take a tarball"
  require_go
  binary=$repo/dist/docket
  checkmate_bin=$repo/dist/checkmate
  install -d -m 755 "$repo/dist"
  if ! (cd "$repo" && GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -trimpath -ldflags='-s -w' -o "$binary" ./cmd/docket && GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -trimpath -ldflags='-s -w' -o "$checkmate_bin" ./cmd/checkmate); then
    die "offline Go build failed. Dependencies were not satisfied from vendor/."
  fi
  [[ -x $binary && -x $checkmate_bin ]] || die "Go reported success and left no binary. That is not success."
else
  if [[ -z $tarball ]]; then
    [[ -d $repo/dist/releases ]] || die "no dist/releases directory. Build a tarball first, or pass its path."
    tarball=$(find "$repo/dist/releases" -maxdepth 1 -type f -name 'docket-*-linux-amd64.tar.gz' -printf '%T@ %p\n' | sort -nr | awk 'NR==1 { print substr($0, index($0,$2)) }')
    [[ -n $tarball ]] || die "no docket-*-linux-amd64.tar.gz under dist/releases"
  fi
  [[ -f $tarball && ! -L $tarball ]] || die "tarball is not a regular file: $tarball"
  [[ -f ${tarball}.sha256 && ! -L ${tarball}.sha256 ]] || die "checksum file is missing beside the tarball"
  (cd -- "$(dirname -- "$tarball")" && sha256sum -c "$(basename -- "${tarball}.sha256")") >/dev/null || die "checksum verification failed: $tarball"
  extract_tmp=$(mktemp -d "${TMPDIR:-/tmp}/docket-install.XXXXXXXX")
  tar -xzf "$tarball" -C "$extract_tmp"
  archive_name=$(find "$extract_tmp" -mindepth 1 -maxdepth 1 -type d -printf '%f\n')
  [[ $(printf '%s\n' "$archive_name" | wc -l) -eq 1 && -x $extract_tmp/$archive_name/bin/docket ]] || die "archive does not contain bin/docket"
  [[ -x $extract_tmp/$archive_name/bin/checkmate ]] || die "archive does not contain bin/checkmate"
  binary=$extract_tmp/$archive_name/bin/docket
  checkmate_bin=$extract_tmp/$archive_name/bin/checkmate
  if [[ -f $extract_tmp/$archive_name/scripts/docket-completion.bash ]]; then
    completion_src=$extract_tmp/$archive_name/scripts/docket-completion.bash
  fi
  if [[ -f $extract_tmp/$archive_name/scripts/checkmate-completion.bash ]]; then
    checkmate_completion=$extract_tmp/$archive_name/scripts/checkmate-completion.bash
  fi
fi

install -d -m 755 "$prefix/bin"
install -m 755 "$binary" "$prefix/bin/docket"
install -m 755 "$checkmate_bin" "$prefix/bin/checkmate"
ensure_path "$prefix/bin"
[[ -f $completion_src && -f $checkmate_completion ]] || die "completion script is missing"
prefix_comp=$prefix/share/bash-completion/completions
install -d -m 755 "$prefix/share/bash-completion/completions"
install -m 644 "$completion_src" "$prefix_comp/docket"
install -m 644 "$checkmate_completion" "$prefix_comp/checkmate"
comp_dir=/usr/share/bash-completion/completions
[[ -d $comp_dir ]] || comp_dir=/etc/bash_completion.d
if [[ -d $comp_dir && -w $comp_dir ]]; then
  install -m 644 "$completion_src" "$comp_dir/docket"
  install -m 644 "$checkmate_completion" "$comp_dir/checkmate"
  printf 'COMPLETION %s\n' "$comp_dir/docket"
elif [[ -d $comp_dir ]] && command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo install -m 644 "$completion_src" "$comp_dir/docket"
  sudo install -m 644 "$checkmate_completion" "$comp_dir/checkmate"
  printf 'COMPLETION %s\n' "$comp_dir/docket"
else
  printf 'install-docket: system completion directory is not writable; installed completions under %s\n' "$prefix_comp" >&2
  printf 'COMPLETION %s\n' "$prefix_comp/docket"
fi
user_completion=${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/docket
if [[ -f $user_completion && ! -L $user_completion && $user_completion != $prefix_comp/docket ]]; then
  rm -f -- "$user_completion"
fi
printf 'INSTALLED %s\n' "$prefix/bin/docket"
printf 'INSTALLED %s\n' "$prefix/bin/checkmate"
"$prefix/bin/docket" batch-cklb --help >/dev/null
"$prefix/bin/docket" quarter --help >/dev/null
"$prefix/bin/docket" tailoring rehash --help >/dev/null
