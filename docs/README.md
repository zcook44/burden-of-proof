# Burden of Proof

Offline conversion of saved OpenSCAP results in a host inventory tree into private STIG Viewer 3 CKLB **review** checklists. The Go application does not run scans, sign off findings, or deliver evidence. Those later pipeline stages are out of scope until conversion is verified for each OS.

## Build and convert

From the repository root on Linux with Go 1.22+ (vendored dependency; no runtime network access):

```sh
install -d -m 700 dist
GOPROXY=off GOSUMDB=off go build -mod=vendor -o dist/stig-evidence ./cmd/stig-evidence
./dist/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/extracted-stig-library --dry-run
./dist/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/extracted-stig-library
```

The caller supplies the inventory root; no lab path is compiled in. Each scan's SSG XCCDF Benchmark ID selects its RHEL 7, 8, 9, or 10 family, and the library selects the newest eligible **extracted manual DISA XCCDF for that family** on each invocation. A library of ZIPs alone is insufficient. Use `--benchmark /private/official.xml` instead of `--library-root` only for a pinned, single-OS conversion.

Place `<prefix>.results.xml` or `<prefix>.results.xccdf.xml` in a directory whose basename equals the XCCDF target host. Same-prefix `<prefix>.report.html` enriches executed checks and item comparisons; `<prefix>.results.arf.xml` adds collected host values when HTML also exists. XCCDF-only results are accepted, but no unobserved values are invented. The application writes `-ASSESSMENT.cklb` plus a byte-bound `.cklb.provenance.json` beside each run in owner-private storage. It never silently overwrites changed output. Numeric V/SV mapping uses explicit newer SSG `V-…` or older SSG `SV-…` references; it is a mapping convention, not proof of semantic equivalence. Missing or ambiguous controls remain Not Reviewed. See [batch converter](BATCH-CKLB.md) for all input, permission, and output rules.

**Verification status:** The Go v6 batch tool converted all five available real saved-scan bundles (RHEL 8 ×1, RHEL 9 ×3, RHEL 10 ×1) against matching official manual benchmarks. Their CKLB bytes are identical to the externally schema-validated v5 review checklists; an independent Go readback checked all five v6 pairs' control IDs/statuses, complete raw-reference inventory, absolute input paths, hashes and owner-private modes. A Go rerun from another working directory skipped all five without replacing them. RHEL 8's older SSG `SV-…` references mapped 329 of 371 official controls to candidate statuses; 42 remained Not Reviewed. Regression tests now reject dual V/SV references to the same numeric control as ambiguous and require absolute provenance in single-scan assessment views. These are unsigned review candidates, not approved assessments. Synthetic mixed-tree tests cover RHEL 7/8/9/10; **real** RHEL 7 results and STIG Viewer GUI import are still outstanding. See [Go-only scope](GO-MIGRATION.md) for limitations.

The legacy tailoring and signed-release workflow is retired, not ported. **No signed-release, signature verification, or evidence-publication command exists here.** See the [Go workflow](WORKFLOW.md) and [asset contract](../contracts/asset-record-v1.md); a separate authorized process must handle signoff and delivery. Keep raw scans, approvals, generated checklists, keys, and host evidence private and out of Git; `.gitignore` is not a security boundary.
