# Shared source-build check for package-ceasefire.sh and install-ceasefire.sh.
# Source this file. The installed docket and checkmate commands do not need Go.
ceasefire_go_help() {
  local running=${1:-not installed}
  cat >&2 <<EOF
This source build needs Go 1.22 or newer. Verified toolchains are Go 1.22.2 and Go 1.27.3.
The running compiler is: ${running}
GOPROXY=off, GOSUMDB=off, and GOTOOLCHAIN=local are set, so this build will not download a compiler or a module.

On a connected machine, download a linux-amd64 Go tarball for 1.22.2 or any newer release from https://go.dev/dl/ and copy that file to this build host. For the Go 1.22.2 archive:

  curl -fsSL -o go1.22.2.linux-amd64.tar.gz https://go.dev/dl/go1.22.2.linux-amd64.tar.gz
  rm -rf "\$HOME/sdk/go"
  mkdir -p "\$HOME/sdk"
  tar -C "\$HOME/sdk" -xzf go1.22.2.linux-amd64.tar.gz
  export PATH="\$HOME/sdk/go/bin:\$PATH"
  go version

A host that only runs the installed docket and checkmate commands does not need Go.
EOF
}

ceasefire_require_go() {
  if ! command -v go >/dev/null 2>&1; then
    ceasefire_go_help "not installed"
    return 1
  fi
  local version major minor
  version=$(go env GOVERSION 2>/dev/null || true)
  version=${version#go}
  if [[ ! $version =~ ^([0-9]+)\.([0-9]+) ]]; then
    ceasefire_go_help "$version"
    return 1
  fi
  major=${BASH_REMATCH[1]}
  minor=${BASH_REMATCH[2]}
  if (( major < 1 || (major == 1 && minor < 22) )); then
    ceasefire_go_help "go${version}"
    return 1
  fi
  return 0
}
