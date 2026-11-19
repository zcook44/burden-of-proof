# Disconnected Linux release

Build a runtime bundle on a connected Linux/amd64 machine with Go 1.22 or newer and the checked-in `vendor/` tree. Go 1.22.2 and Go 1.27.3 both build this module. `go.mod` says `go 1.22.0`. `scripts/package-disconnected.sh` and `scripts/install-docket.sh --from-source` set `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, and `CGO_ENABLED=0`, then refuse to start when `go version` is older than 1.22. They do not download a compiler or a module. The message names the running compiler and the offline install below.

On a connected machine, download `go1.22.2.linux-amd64.tar.gz` (or any newer official tarball) from https://go.dev/dl/ and copy that file to the build host:

```sh
rm -rf "$HOME/sdk/go"
mkdir -p "$HOME/sdk"
tar -C "$HOME/sdk" -xzf go1.22.2.linux-amd64.tar.gz
export PATH="$HOME/sdk/go/bin:$PATH"
go version
```

A host that only runs the installed `docket` and `checkmate` binaries does not need Go, a module cache, or a network.

```sh
./scripts/package-disconnected.sh VERSION ./dist/releases
./scripts/install-docket.sh
```

`install-docket.sh` picks the newest `dist/releases/docket-*-linux-amd64.tar.gz`, checks the sibling `.sha256`, and installs `docket` and `checkmate` onto `~/.local/bin` (or `--prefix`). If that `bin` directory is not on `PATH`, the installer prints `export PATH="<prefix>/bin:$PATH"` and still exits 0. Release 1.0.1 was published before the rename, so its archive is still called `stig-evidence-1.0.1-linux-amd64.tar.gz`. Archives built from this tree use the `docket-` prefix. `--from-source` is for a checkout that contains `vendor/` and `scripts/require-go.sh`. The release archive does not contain them.

The archive contains `bin/docket`, `bin/checkmate`, bash completion for both commands, the executable Bash `scripts/preflight-offline.sh`, the Python 3 `scripts/generate-cisco-tailoring.py` (Python is needed only to run this optional generator), four example `templates/RHEL_{7,8,9,10}_STIG.tailoring.yaml` files, partial schema v3 Cisco root tailoring examples under `cisco-library/`, `schemas/SV3_CKLB_1_0_JSON_SCHEMA.json` and its [provenance notice](../schemas/PROVENANCE.md), repository and `docs/*.md` documentation, the asset contract, **both** non-executable `docs/snapshots/oscap_scan.yml` and `docs/snapshots/run-lab-oscap.sh`, `RELEASE.txt` (including source commit and dirty state), and `SHA256SUMS` for every included file. The DISA schema is for **optional CKLB validation** through `checkmate --validate`, not a converter input. The upstream ZIP has no explicit redistribution notice; verify organizational authority before sharing the bundle beyond authorized recipients. It does **not** contain the live `/scratch/ansible` playbook/wrapper, official XCCDF benchmarks (including the 25 Cisco XMLs tracked in this source repository), SSG scan results, credentials, approvals, or signing material. The outer SHA-256 file detects transfer corruption **only if its expected hash arrives through an independently trusted channel**; neither checksum is a publisher signature. Do not execute an untrusted archive merely because its adjacent hash matches.

On the disconnected Linux/amd64 host, after authenticating the bundle and its expected hash through your approved transfer process:

```sh
install -d -m 700 "$HOME/docket-releases"
(cd /transfer && sha256sum -c docket-VERSION-linux-amd64.tar.gz.sha256)
tar -tzf /transfer/docket-VERSION-linux-amd64.tar.gz
tar -xzf /transfer/docket-VERSION-linux-amd64.tar.gz -C "$HOME/docket-releases"
"$HOME/docket-releases/docket-VERSION-linux-amd64/scripts/install-docket.sh" \
  /transfer/docket-VERSION-linux-amd64.tar.gz
```

The installer always copies bash completion for `docket` and `checkmate` under `$prefix/share/bash-completion/completions/`. It also copies them to `/usr/share/bash-completion/completions/` (or `/etc/bash_completion.d/` when that is the directory present) when that directory is writable or passwordless sudo is available. A system directory that is not writable does not fail the install. Completion covers subcommands, including `tailoring check`, `tailoring rehash`, `tailoring migrate`, and `quarter`. When `DOCKET_CONFIG` or `~/.config/docket/config.yaml` names a library, completion also offers benchmark IDs and host directory names from that tree. Zsh and fish are not included.

The same binary runs the Cisco commands. [Install and run](README.md) is the shared procedure: one library, one hostname rule, one command table.

The checksum command above expects the `.tar.gz` beside its `.sha256` file. If transfer paths differ, place the two files together in a protected directory before verification. Do not blindly extract an archive whose entries you have not checked for absolute paths, `..` traversal, or links. Build a signed distribution with an independently trusted verification key if your release process requires publisher authentication; this script does not claim to implement that trust path.

Supply official extracted DISA manual XCCDF files separately in one owner-private library directory. RHEL and Cisco manuals may share it. Manual XML files may be mode `0644`; they must not be group-writable or executable. Library directories stay mode `0700`. Tailoring files, scans, device configs, and generated checklists stay mode `0600`. The packaged tailoring YAML files are **examples only**, and the RHEL 9 example contains a lab-specific `not_a_finding` status; do not install them as approved site policy. Leave them out of the selected library until independently reviewed and authorized for **every host of that OS**. Their `benchmark_sha256` is `rehash-me` until `docket tailoring rehash`. The converter selects the newest matching manual under the library, including files in subdirectories. After staging scan inputs and benchmarks, run `docket quarter --dry-run` or the Bash preflight before the first conversion write. `checkmate` is the second binary in this archive.

```sh
./scripts/preflight-offline.sh \
  --converter "$PWD/bin/docket" \
  --input-root /private/inventory \
  --library-root /private/stig-library
```

`checkmate` is in the archive next to `docket`. Add both `--checkmate` and `--checklist-root` to the preflight. `--schema` is valid only with both. A tailoring check failure stops the preflight. Prefer `docket quarter --dry-run` for the conversion preview:

```sh
./scripts/preflight-offline.sh \
  --converter "$PWD/bin/docket" \
  --input-root /private/inventory \
  --library-root /private/stig-library \
  --checkmate "$(command -v checkmate)" \
  --checklist-root /private/checklists \
  --schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"
```

The Bash preflight checks the input, library, and (if separate) checklist roots as canonical absolute owner-owned private trees without symlinks or special files. It verifies a root's `SHA256SUMS` when that file is present. It prints the benchmark and any tailoring file `batch-cklb --dry-run` would use. With both Checkmate arguments it counts `--list` output. It does not certify benchmark provenance, policy approval, schema licensing, fresh guest SCAP content, or Checkmate's own provenance. It never writes an assessment, scans a guest, or replaces human review. Resolve failures and read the dry-run selections before any intentional `batch-cklb` write.

Cisco review uses that same binary and the same library root. `cisco-cklb` and `cisco-batch` take `--dry-run` and write nothing until you omit it. `cisco-xccdf` writes the device-named result on the first successful run; there is no preview flag to hide behind. It applies `<benchmark-id>.tailoring.yaml` when that file sits beside `scan.running-config`. `xccdf-cklb` copies that result into `<host>.cklb` and writes `<host>.cklb.provenance.json`. The Bash preflight remains the RHEL check. Supply the running configuration and device identity from outside this archive. [Install and run](README.md). [Scan fields](NETWORK-SCAN.md).

For a source build instead of the binary bundle, copy this repository **including `vendor/`** to the build host that already has Go 1.22 or newer, then run `./scripts/install-docket.sh --from-source`. That uses the same offline environment as the package script. A Git commit identifier in `RELEASE.txt` does not identify uncommitted source bytes; make a clean, reviewed commit before representing the package as a formal source release. The installed binaries still need no Go.
