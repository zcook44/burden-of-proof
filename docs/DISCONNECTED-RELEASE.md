# Disconnected Linux release

Build a runtime bundle on a Linux/amd64 build host with Go 1.22+ and the checked-in `vendor/` tree. The build script forces `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, and `CGO_ENABLED=0`; it runs the Go suite before creating the archive. No Go toolchain or network connection is needed to **run** the packaged CLI.

```sh
./scripts/package-disconnected.sh 1.0.0 ./dist/releases
(cd dist/releases && sha256sum -c stig-evidence-1.0.0-linux-amd64.tar.gz.sha256)
```

The archive contains `bin/stig-evidence`, `scripts/preflight-offline.sh`, `templates/RHEL_{7,8,9,10}_STIG.tailoring.yaml`, documentation (including non-executable scan-source snapshots), `RELEASE.txt` (including source commit and dirty state), and `SHA256SUMS` for every included file. It does **not** contain licensed official benchmarks, SSG scan results, credentials, approvals, or signing material. The outer SHA-256 file detects transfer corruption **only if its expected hash arrives through an independently trusted channel**; neither checksum is a publisher signature. Do not execute an untrusted archive merely because its adjacent hash matches.

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

Supply official extracted DISA manual XCCDF files separately in an owner-private library directory. The packaged tailoring YAML files are **examples only**; do not install them as approved site policy. The converter automatically selects matching tailoring YAML from the library, so review every listed tailoring selection before permitting a conversion write. To check a private deployment without a scan or an edit:

```sh
./scripts/preflight-offline.sh \
  --converter "$PWD/bin/stig-evidence" \
  --input-root /private/inventory \
  --library-root /private/stig-library \
  --checkmate /private/checkmate/checkmate \
  --checklist-root /private/checklists
```

The Bash preflight checks that each root is a canonical, owner-private tree without symlinks or special files, verifies `SHA256SUMS` when present, prints converter benchmark and tailoring selections using `batch-cklb --dry-run`, and counts Checkmate `--list` output. Omit both `--checkmate` and `--checklist-root` if no CKLBs have been created; add `--schema /private/schema.json` only if you deliberately want Checkmate's optional local-schema validation. The preflight does not certify benchmark provenance, policy approval, schema licensing, or a fresh guest's SCAP installation. It never writes an assessment. Resolve failures and review the dry-run selections before any intentional `batch-cklb` write; a production library must contain only the approved policies intended for that run.

For an offline source build instead of the binary bundle, transfer this repository **including `vendor/` and all uncommitted changes intended for release**, then run `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=vendor go test ./...` and `go build -mod=vendor ./cmd/stig-evidence`. A Git commit identifier in `RELEASE.txt` does not identify uncommitted source bytes; make a clean, reviewed commit/tag before representing the package as a formal source release.
