# Go-only review converter

`stig-evidence` is the sole tracked application. This repository owns the evidence-side handoff check, reconciliation and CKLB review conversion; the lab lives in a separate repository. It builds offline with Go 1.22+ and vendored HTML/YAML parsers; the packaged static Linux/amd64 CLI needs no Go or Python runtime. A simple per-OS YAML supplies checklist comments and decisions, but the retired *signed-release* tailoring implementation was **not** ported. No command in this repository verifies an approval signature, releases an official assessment, or delivers evidence. See [quick start](README.md), [disconnected release](DISCONNECTED-RELEASE.md), [workflow](WORKFLOW.md), and the [asset record contract](../contracts/asset-record-v1.md) for the resulting boundaries.

## Commands

```sh
GOPROXY=off GOSUMDB=off go test -mod=vendor ./...
install -d -m 700 dist
GOPROXY=off GOSUMDB=off go build -mod=vendor -o dist/stig-evidence ./cmd/stig-evidence
./dist/stig-evidence asset-check --asset /private/asset.json --pre /private/pre.xml --host node.example.test
./dist/stig-evidence reconcile --scan /private/ssg-results.xml --benchmark /private/official.xml --out /private/candidates.json
./dist/stig-evidence draft-cklb --scan /private/ssg-results.xml --benchmark /private/official.xml --out /private/review.cklb
./dist/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/extracted-stig-library
```

- `asset-check` verifies a v1 asset record against the supplied pre-scan bytes. It does **not** attest lab provenance, baseline state, or authorization.
- `reconcile` creates private candidate mapping JSON, never an official DISA scan result. Every TestResult rule-result (including unmatched and unselected) retains raw outcome, original reference text/href, and any numeric V join key. Ambiguous source references cannot establish a passing control.
- `draft-cklb` creates a no-overwrite private checklist. `--assessment-view --html-report` adds executed-check/observed-value presentation; optional `--arf` adds collected OVAL values. `--operator-approved` is only an unsigned caller assertion for a single ARF assessment view, not a release gate or signature.
- `batch-cklb` recurses a host inventory and independently selects the newest eligible extracted manual benchmark for each detected RHEL 7/8/9/10 OS. It reads optional per-OS YAML at the library root, then writes one private CKLB and byte-bound provenance sidecar per saved scan. Untailored outputs retain the v10 identity; tailored outputs use a separate v11 identity bound to the policy bytes. Earlier outputs remain unchanged. [Exact pairing, library and no-overwrite rules](BATCH-CKLB.md).

A numeric `V-…` or historical `SV-…r…_rule` reference is an explicit join candidate, not independently verified check-equivalence. Missing, unselected, ambiguous, or unchecked controls remain Not Reviewed unless an administrator explicitly supplies a per-OS checklist decision. The packaged binary has converted copied real scans for all four RHEL families with their official benchmarks and bundled YAML templates; GUI import has not been exercised by this CLI. Keep scans, benchmarks, review files, and sidecars private and Git-ignored.

For initial offline deployment, the separately packaged Bash `scripts/preflight-offline.sh` checks private scan/library trees and any `SHA256SUMS`, then calls the Go `batch-cklb --dry-run` before an intentional conversion write. Optional separately installed Checkmate inventories existing CKLBs and can validate them with a supplied schema; it is **not** a Go subcommand, converter, or approval gate. The bundled per-OS YAML templates (including a RHEL 9 lab-specific status override) are unapproved examples, not site policy; copying them to the selected library activates their decisions for every host of that OS. See [release and preflight](DISCONNECTED-RELEASE.md) and [review boundary](WORKFLOW.md#checkmate-is-a-separate-tool).
