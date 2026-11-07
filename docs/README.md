# Burden of Proof

Independent, offline XCCDF policy tailoring and fail-closed STIG Viewer 3 CKLB evidence packaging. No VM, scanner, installation, or licensed-media operations occur here. The `stig_evidence` package uses Python's standard library plus `jsonschema` for release validation; `openssl` is required to verify detached approval signatures. The Go CLI supports recursive, offline OpenSCAP-to-CKLB review conversion; Python remains the only evidence-release implementation. See [batch converter](BATCH-CKLB.md) and [Go migration](GO-MIGRATION.md).

Run from this repository root:

```sh
python -m stig_evidence.cli tailor --policy stig_evidence/policy.example.json --benchmark /path/to/official-benchmark.xml --benchmark-href official-benchmark.xml --out /private/tailoring.xml
python -m stig_evidence.cli cklb --policy /private/policy.json --benchmark /private/official-benchmark.xml --asset /private/asset.json --pre /private/pre.xml --post /private/post.xml --coverage /private/coverage.xml --tailoring /private/tailoring.xml --schema /private/official-cklb-1.0-schema.json --approval-ledger /private/ledger.json --approval-signature /private/ledger.sig --trusted-key /private/isso.pub --host node.example.test --evidence-dir /private/evidence/run-001
```

The example policy intentionally contains placeholder approvals and cannot be released. The CKLB schema is supplied externally and must match the pinned official DISA 1.0 SHA-256 in `stig_evidence/cklb.py`. The destination must be absent and its parent must be an owner-owned, nonsymlinked directory with mode **0700**. Input symlinks are refused; copied inputs and outputs are owner-only. Keep private keys **outside** this repository; only a trusted public key and signature are release inputs. Verify the trusted key's owner out of band.

For recursive Go conversion of a directory of saved OpenSCAP runs (no scanner or VM access), build and run with a caller-supplied path:

```sh
install -d -m 700 dist
GOPROXY=off GOSUMDB=off go build -mod=vendor -o dist/stig-evidence ./cmd/stig-evidence
./dist/stig-evidence batch-cklb --input-root /path/to/lab_results --library-root /private/extracted-stig-library --dry-run
./dist/stig-evidence batch-cklb --input-root /path/to/lab_results --library-root /private/extracted-stig-library
```

The input root is not hard-coded; change `--input-root` on each invocation. `--library-root` selects the newest extracted RHEL 9 manual XCCDF by verified benchmark version and release metadata on every invocation. Extract the product ZIP inside the quarterly library first; a directory containing only ZIP archives is not sufficient. For an intentionally pinned historical conversion, use `--benchmark /private/official.xml` **instead of** `--library-root`. Numeric V/SV matching is the default mapping rule. Complete scan bundles are paired by prefix and written as private `-ASSESSMENT.cklb` review files beside their inputs. Each assessment has an adjacent `.cklb.provenance.json` sidecar binding the exact checklist bytes to full input hashes and per-control mapping details; keep both files together. Repeated runs verify both outputs before skipping. See [batch converter](BATCH-CKLB.md) for pairing, safety, and validation details. These review files are not signed releases.

`.gitignore` is only a convenience, not a secret-control boundary: before every commit, review the staged file list and staged diff for scan inputs, signing material, approvals, and generated evidence (including files outside the ignored names). Do not commit any such material.

For tests, supply the externally obtained official schema so the full synthetic release test is exercised:

```sh
STIG_EVIDENCE_SCHEMA=/path/to/official-cklb-1.0-schema.json python -m unittest discover -s tests -v
```

Without it, the two official-schema-dependent tests skip. See [workflow](WORKFLOW.md) and [asset contract](../contracts/asset-record-v1.md). Synthetic fixtures establish code paths and fail-closed behavior, **not** authenticity of a real scan, an actual clean baseline, approval authority, STIG Viewer import, or operational compliance. Independent ISSO review and signed per-asset acceptance remain outstanding after release.
