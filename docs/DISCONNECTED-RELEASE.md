# Disconnected Linux release

Build a runtime bundle on a Linux/amd64 build host with Go 1.22+ and the checked-in `vendor/` tree. The build script forces `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, and `CGO_ENABLED=0`; it runs the Go suite before creating the archive. No Go toolchain or network connection is needed to **run** the packaged CLI.

```sh
./scripts/package-disconnected.sh 1.0.0 ./dist/releases
(cd dist/releases && sha256sum -c stig-evidence-1.0.0-linux-amd64.tar.gz.sha256)
```

The archive contains `bin/stig-evidence`, the executable Bash `scripts/preflight-offline.sh`, the Python 3 `scripts/generate-cisco-tailoring.py` (Python is needed only to run this optional generator), four example `templates/RHEL_{7,8,9,10}_STIG.tailoring.yaml` files, `schemas/SV3_CKLB_1_0_JSON_SCHEMA.json` and its [provenance notice](../schemas/PROVENANCE.md), repository and `docs/*.md` documentation, the asset contract, **both** non-executable `docs/snapshots/oscap_scan.yml` and `docs/snapshots/run-lab-oscap.sh`, `RELEASE.txt` (including source commit and dirty state), and `SHA256SUMS` for every included file. The DISA schema is for **optional external CKLB validation**, not a converter input. The upstream ZIP has no explicit redistribution notice; verify organizational authority before sharing the bundle beyond authorized recipients. It does **not** contain the live `/scratch/ansible` playbook/wrapper, official XCCDF benchmarks (including the 25 Cisco XMLs tracked in this source repository), the 25 tracked all-`auto` Cisco YAML inventories, SSG scan results, Checkmate, credentials, approvals, or signing material. The outer SHA-256 file detects transfer corruption **only if its expected hash arrives through an independently trusted channel**; neither checksum is a publisher signature. Do not execute an untrusted archive merely because its adjacent hash matches.

On the disconnected Linux/amd64 host, after authenticating the bundle and its expected hash through your approved transfer process:

```sh
install -d -m 700 "$HOME/stig-evidence-releases"
(cd /transfer && sha256sum -c stig-evidence-1.0.0-linux-amd64.tar.gz.sha256)
tar -tzf /transfer/stig-evidence-1.0.0-linux-amd64.tar.gz  # inspect paths first
tar -xzf /transfer/stig-evidence-1.0.0-linux-amd64.tar.gz -C "$HOME/stig-evidence-releases"
cd "$HOME/stig-evidence-releases/stig-evidence-1.0.0-linux-amd64"
sha256sum -c SHA256SUMS
./bin/stig-evidence batch-cklb --help
```

The checksum command above expects the `.tar.gz` beside its `.sha256` file. If transfer paths differ, place the two files together in a protected directory before verification. Do not blindly extract an archive whose entries you have not checked for absolute paths, `..` traversal, or links. Build a signed distribution with an independently trusted verification key if your release process requires publisher authentication; this script does not claim to implement that trust path.

Supply official extracted DISA manual XCCDF files separately in an owner-private library directory. The packaged tailoring YAML files are **examples only**, and the RHEL 9 example contains a lab-specific `not_a_finding` status; do not install them as approved site policy. Leave them out of the selected library until independently reviewed and authorized for **every host of that OS**. The converter automatically selects any matching YAML at the library root. After staging scan inputs and benchmarks, run this Bash **initial-deployment preflight before the first conversion write**; Checkmate is a separately supplied optional tool, not bundled with or invoked by the Go converter:

```sh
./scripts/preflight-offline.sh \
  --converter "$PWD/bin/stig-evidence" \
  --input-root /private/inventory \
  --library-root /private/stig-library \
  --checkmate /private/checkmate/checkmate \
  --checklist-root /private/checklists
```

The Bash preflight checks the input, library, and (if separate) checklist roots as canonical absolute owner-owned private trees without symlinks or special files; it verifies a root's `SHA256SUMS` **when present**, not when absent. It prints converter benchmark and optional tailoring selections using `batch-cklb --dry-run`; with both Checkmate arguments it counts `--list` output. Omit both `--checkmate` and `--checklist-root` if not using Checkmate (including before any CKLB exists); `--schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"` is valid only with both and requests Checkmate `--validate --schema`. The preflight does not certify benchmark provenance, policy approval, schema licensing, fresh guest SCAP content, or Checkmate's own provenance. It never writes an assessment, scans a guest, or replaces human review. Resolve failures and review the dry-run selections before any intentional `batch-cklb` write.

For an offline source build instead of the binary bundle, transfer this repository **including `vendor/` and all uncommitted changes intended for release**, then run `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=vendor go test ./...` and `go build -mod=vendor ./cmd/stig-evidence`. A Git commit identifier in `RELEASE.txt` does not identify uncommitted source bytes; make a clean, reviewed commit/tag before representing the package as a formal source release.
