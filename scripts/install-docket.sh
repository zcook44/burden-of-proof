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
  command -v go >/dev/null 2>&1 || die "Go is not installed. A source install cannot fetch a toolchain."
  local version major minor
  version=$(go env GOVERSION 2>/dev/null || true)
  version=${version#go}
  [[ $version =~ ^([0-9]+)\.([0-9]+) ]] || die "cannot read the Go version. Refusing to guess."
  major=${BASH_REMATCH[1]}
  minor=${BASH_REMATCH[2]}
  if (( major < 1 || (major == 1 && minor < 22) )); then
    die "Go ${version} is older than 1.22. The vendored build will not start."
  fi
  [[ -f $repo/vendor/modules.txt && -d $repo/cmd/docket ]] || die "vendor/ or cmd/docket is missing. Refusing to download modules."
}

ensure_path() {
  local bindir=$1 rc
  case :$PATH: in
    *:"$bindir":*) return 0 ;;
  esac
  [[ $bindir == "$HOME/.local/bin" ]] || die "$bindir is not on PATH. Use --prefix \"\$HOME/.local\" or add that directory yourself."
  local line='export PATH="$HOME/.local/bin:$PATH"'
  for rc in "$HOME/.profile" "$HOME/.bashrc"; do
    if [[ -L $rc ]]; then
      die "refusing to follow a symlink while updating PATH: $rc"
    fi
    if [[ ! -e $rc ]]; then
      touch "$rc" || die "cannot create $rc to put ~/.local/bin on PATH"
    fi
    [[ -w $rc ]] || die "cannot update $rc to put ~/.local/bin on PATH"
    if ! grep -Fq '.local/bin' "$rc"; then
      printf '\n%s\n' "$line" >> "$rc"
    fi
  done
  printf 'install-docket: added ~/.local/bin to PATH in ~/.profile and ~/.bashrc. Open a new shell.\n' >&2
}

binary=
if [[ $from_source -eq 1 ]]; then
  [[ -z $tarball ]] || die "--from-source does not take a tarball"
  require_go
  binary=$repo/dist/docket
  install -d -m 755 "$repo/dist"
  if ! (cd "$repo" && GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -trimpath -ldflags='-s -w' -o "$binary" ./cmd/docket); then
    die "offline Go build failed. Dependencies were not satisfied from vendor/."
  fi
  [[ -x $binary ]] || die "Go reported success and left no binary. That is not success."
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
  binary=$extract_tmp/$archive_name/bin/docket
  if [[ -f $extract_tmp/$archive_name/scripts/docket-completion.bash ]]; then
    completion_src=$extract_tmp/$archive_name/scripts/docket-completion.bash
  fi
fi

install -d -m 755 "$prefix/bin"
install -m 755 "$binary" "$prefix/bin/docket"
ensure_path "$prefix/bin"
[[ -f $completion_src ]] || die "completion script is missing"
comp_dir=/usr/share/bash-completion/completions
[[ -d $comp_dir ]] || comp_dir=/etc/bash_completion.d
[[ -d $comp_dir ]] || die "bash-completion is not installed. Neither /usr/share/bash-completion/completions nor /etc/bash_completion.d exists."
if [[ -w $comp_dir ]]; then
  install -m 644 "$completion_src" "$comp_dir/docket"
elif command -v sudo >/dev/null 2>&1; then
  sudo install -m 644 "$completion_src" "$comp_dir/docket" || die "could not install the completion for every user into $comp_dir"
else
  die "cannot write $comp_dir and sudo is not available"
fi
user_completion=${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/docket
if [[ -f $user_completion && ! -L $user_completion ]]; then
  rm -f -- "$user_completion"
fi
printf 'COMPLETION %s\n' "$comp_dir/docket"
printf 'INSTALLED %s\n' "$prefix/bin/docket"
"$prefix/bin/docket" batch-cklb --help >/dev/null
