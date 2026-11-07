# Go-only review converter

`stig-evidence` is the sole tracked application. It runs offline with Go 1.22+ and the vendored HTML parser; no Python runtime or package is required for conversion. The retired tailoring and signed-release implementation was **not** ported. No command in this repository verifies an approval signature, releases an official assessment, or delivers evidence. See [workflow](WORKFLOW.md) for the resulting operational boundary.

## Commands

```sh
GOPROXY=off GOSUMDB=off go test -mod=vendor ./...
GOPROXY=off GOSUMDB=off go build -mod=vendor -o dist/stig-evidence ./cmd/stig-evidence
./dist/stig-evidence asset-check --asset /private/asset.json --pre /private/pre.xml --host node.example.test
./dist/stig-evidence reconcile --scan /private/ssg-results.xml --benchmark /private/official.xml --out /private/candidates.json
./dist/stig-evidence draft-cklb --scan /private/ssg-results.xml --benchmark /private/official.xml --out /private/review.cklb
./dist/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/extracted-stig-library
```

- `asset-check` verifies a v1 asset record against the supplied pre-scan bytes. It does **not** attest lab provenance, baseline state, or authorization.
- `reconcile` creates private candidate mapping JSON, never an official DISA scan result. Every TestResult rule-result (including unmatched and unselected) retains raw outcome, original reference text/href, and any numeric V join key. Ambiguous source references cannot establish a passing control.
- `draft-cklb` creates a no-overwrite private checklist. `--assessment-view --html-report` adds executed-check/observed-value presentation; optional `--arf` adds collected OVAL values. `--operator-approved` is only an unsigned caller assertion for a single ARF assessment view, not a release gate or signature.
- `batch-cklb` recurses a host inventory and independently selects the newest eligible extracted manual benchmark for each detected RHEL 7/8/9/10 OS. It writes one private review CKLB and byte-bound provenance sidecar per saved scan. New versions use `assessment-provenance-v6`; older outputs remain unchanged. No global approval is applied. [Exact pairing, library and no-overwrite rules](BATCH-CKLB.md).

A numeric `V-…` or historical `SV-…r…_rule` reference is an explicit join candidate, not independently verified check-equivalence. Missing, unselected, ambiguous, or unchecked controls remain Not Reviewed. Schema validation against the separately obtained official CKLB 1.0 schema and STIG Viewer import remain external checks. Five real RHEL 8/9/10 bundles were converted with prior Go v5 outputs; v6 rerun verification is recorded in [batch converter](BATCH-CKLB.md). Real RHEL 7 results and GUI import are still outstanding. Keep scans, benchmarks, review files, and sidecars private and Git-ignored.
