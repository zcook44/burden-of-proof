# Disconnected Linux release

Build a runtime bundle on a Linux/amd64 build host with Go 1.22+ and the checked-in `vendor/` tree. The build script forces `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, and `CGO_ENABLED=0`; it runs the Go suite before creating the archive. No Go toolchain or network connection is needed to **run** the packaged CLI.

```sh
./scripts/package-disconnected.sh 1.0.0 ./dist/releases
(cd dist/releases && sha256sum -c stig-evidence-1.0.0-linux-amd64.tar.gz.sha256)
```

The archive contains `bin/stig-evidence`, `templates/RHEL_{7,8,9,10}_STIG.tailoring.yaml`, documentation, `RELEASE.txt` (including source commit and dirty state), and `SHA256SUMS` for every included file. It does **not** contain licensed official benchmarks, SSG scan results, credentials, approvals, or signing material. The outer SHA-256 file detects transfer corruption **only if its expected hash arrives through an independently trusted channel**; neither checksum is a publisher signature. Do not execute an untrusted archive merely because its adjacent hash matches.

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

Supply the official extracted DISA manual XCCDF files separately in an owner-private library directory. Install each desired template there as a **mode-0600** file; do not make a protected library public to let a privileged process read it. The example uses an existing private library:

```sh
install -m 600 templates/RHEL_8_STIG.tailoring.yaml /private/stig-library/RHEL_8_STIG.tailoring.yaml
./bin/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/stig-library --dry-run
./bin/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/stig-library
```

Repeat the `install` command for the OS families you intend to use. The per-OS YAML applies to **all** hosts of that OS in the selected inventory; customize the administrator comments and statuses before conversion. `auto` preserves the automated candidate. RHEL 7/10 templates have `rules: []` because there were no verified remediation ignore lists to seed. RHEL 9's passwordless-sudo entry is already an explicit *Not a Finding* administrator decision; review that site-specific choice before deploying the template elsewhere. The converter never scans or remediates guests, and it does not fetch public dependencies at runtime.

For an offline source build instead of the binary bundle, transfer this repository **including `vendor/` and all uncommitted changes intended for release**, then run `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=vendor go test ./...` and `go build -mod=vendor ./cmd/stig-evidence`. A Git commit identifier in `RELEASE.txt` does not identify uncommitted source bytes; make a clean, reviewed commit/tag before representing the package as a formal source release.
