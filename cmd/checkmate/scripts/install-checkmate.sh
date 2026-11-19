#!/usr/bin/env bash
# Unpack a built Checkmate release and put the binary on PATH.
# --from-source builds this checkout and fails if Go or vendor/ cannot
# satisfy the build with the network turned off.
set -euo pipefail
umask 022

usage() {
  printf 'Usage: %s [--prefix DIR] [TARBALL]\n' "${0##*/}" >&2
  printf '       %s --from-source [--prefix DIR]\n' "${0##*/}" >&2
  printf 'Default prefix is $HOME/.local. Default tarball is the newest release/checkmate_*_linux_<this-arch>.tar.gz.\n' >&2
  exit 2
}
die() { printf 'install-checkmate: %s\n' "$*" >&2; exit 1; }

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
completion_src=$script_dir/checkmate-completion.bash
extract_tmp=
trap '[[ -n ${extract_tmp:-} ]] && rm -rf -- "$extract_tmp"' EXIT

machine_arch() {
  case $(uname -m) in
    x86_64) printf amd64 ;;
    aarch64|arm64) printf arm64 ;;
    *) die "this machine is $(uname -m). The release archives are linux/amd64 and linux/arm64." ;;
  esac
}

require_go() {
  command -v go >/dev/null 2>&1 || die "Go is not installed. A source install cannot fetch a toolchain."
  local version need
  version=$(go env GOVERSION 2>/dev/null || true)
  version=${version#go}
  [[ $version =~ ^[0-9]+\.[0-9]+ ]] || die "cannot read the Go version. Refusing to guess."
  need=$(awk '$1=="go" { print $2; exit }' "$repo/go.mod")
  [[ -n $need ]] || die "go.mod does not say which Go this module requires."
  printf '%s\n%s\n' "$need" "$version" | sort -V -C || die "Go ${version} is older than go.mod requires (${need}). Refusing to download a newer toolchain."
  [[ -f $repo/vendor/modules.txt && -f $repo/main.go ]] || die "vendor/ or main.go is missing. Refusing to download modules."
}

ensure_path() {
  local bindir=$1 rc
  case :$PATH: in
    *:"$bindir":*) return 0 ;;
  esac
  [[ $bindir == "$HOME/.local/bin" ]] || die "$bindir is not on PATH. Use --prefix \"\$HOME/.local\" or add that directory yourself."
  local line='export PATH="$HOME/.local/bin:$PATH"'
  for rc in "$HOME/.profile" "$HOME/.bashrc"; do
    [[ -L $rc ]] && die "refusing to follow a symlink while updating PATH: $rc"
    [[ -e $rc ]] || touch "$rc" || die "cannot create $rc to put ~/.local/bin on PATH"
    [[ -w $rc ]] || die "cannot update $rc to put ~/.local/bin on PATH"
    grep -Fq '.local/bin' "$rc" || printf '\n%s\n' "$line" >> "$rc"
  done
  printf 'install-checkmate: added ~/.local/bin to PATH in ~/.profile and ~/.bashrc. Open a new shell.\n' >&2
}

install_completion() {
  [[ -f $completion_src ]] || die "completion script is missing"
  local comp_dir=/usr/share/bash-completion/completions
  [[ -d $comp_dir ]] || comp_dir=/etc/bash_completion.d
  [[ -d $comp_dir ]] || die "bash-completion is not installed. Neither /usr/share/bash-completion/completions nor /etc/bash_completion.d exists."
  if [[ -w $comp_dir ]]; then
    install -m 644 "$completion_src" "$comp_dir/checkmate"
  elif command -v sudo >/dev/null 2>&1; then
    sudo install -m 644 "$completion_src" "$comp_dir/checkmate" || die "could not install the completion for every user into $comp_dir"
  else
    die "cannot write $comp_dir and sudo is not available"
  fi
  local user_completion=${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/checkmate
  [[ -f $user_completion && ! -L $user_completion ]] && rm -f -- "$user_completion"
  printf 'COMPLETION %s\n' "$comp_dir/checkmate"
}

binary=
if [[ $from_source -eq 1 ]]; then
  [[ -z $tarball ]] || die "--from-source does not take a tarball"
  require_go
  binary=$repo/release/checkmate
  install -d -m 755 "$repo/release"
  if ! (cd "$repo" && GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -trimpath -ldflags='-s -w' -o "$binary" .); then
    die "offline Go build failed. Dependencies were not satisfied from vendor/."
  fi
  [[ -x $binary ]] || die "Go reported success and left no binary. That is not success."
else
  if [[ -z $tarball ]]; then
    [[ -d $repo/release ]] || die "no release directory. Build a tarball first, or pass its path."
    arch=$(machine_arch)
    tarball=$(find "$repo/release" -maxdepth 1 -type f -name "checkmate_*_linux_${arch}.tar.gz" -printf '%T@ %p\n' | sort -nr | awk 'NR==1 { print substr($0, index($0,$2)) }')
    [[ -n $tarball ]] || die "no checkmate_*_linux_${arch}.tar.gz under release/"
  fi
  [[ -f $tarball && ! -L $tarball ]] || die "tarball is not a regular file: $tarball"
  sums=$(dirname -- "$tarball")/SHA256SUMS
  base=$(basename -- "$tarball")
  [[ -f $sums && ! -L $sums ]] || die "SHA256SUMS is missing beside the tarball"
  grep -F "  ${base}" "$sums" | (cd -- "$(dirname -- "$tarball")" && sha256sum -c -) >/dev/null || die "checksum verification failed: $tarball"
  extract_tmp=$(mktemp -d "${TMPDIR:-/tmp}/checkmate-install.XXXXXXXX")
  tar -xzf "$tarball" -C "$extract_tmp"
  archive_name=$(find "$extract_tmp" -mindepth 1 -maxdepth 1 -type d -printf '%f\n')
  [[ $(printf '%s\n' "$archive_name" | wc -l) -eq 1 && -x $extract_tmp/$archive_name/checkmate ]] || die "archive does not contain a checkmate binary"
  binary=$extract_tmp/$archive_name/checkmate
  if [[ -f $extract_tmp/$archive_name/scripts/checkmate-completion.bash ]]; then
    completion_src=$extract_tmp/$archive_name/scripts/checkmate-completion.bash
  fi
fi

install -d -m 755 "$prefix/bin"
install -m 755 "$binary" "$prefix/bin/checkmate"
ensure_path "$prefix/bin"
install_completion
printf 'INSTALLED %s\n' "$prefix/bin/checkmate"
"$prefix/bin/checkmate" --help >/dev/null
