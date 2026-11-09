# Quick start: private review conversion

Burden of Proof owns the evidence-side policy and review conversion: it checks a versioned, non-secret [lab asset record](../contracts/asset-record-v1.md), reconciles saved SSG results against official manual XCCDF controls, and writes private CKLB **review** candidates. The lab and its provisioning/scanning live in a separate repository. No lab path is compiled into this CLI, and conversion does not attest the lab's assertions. The CLI does not run scans, sign off findings, or deliver evidence.

[Repository overview](../README.md) · [Batch rules](BATCH-CKLB.md) · [Commands and scope](GO-MIGRATION.md) · [Review workflow](WORKFLOW.md) · [Disconnected release](DISCONNECTED-RELEASE.md)

## Build and convert

From the repository root on Linux with Go 1.22+ (vendored dependency; no runtime network access):

```sh
install -d -m 700 dist
GOPROXY=off GOSUMDB=off go build -mod=vendor -o dist/stig-evidence ./cmd/stig-evidence
./dist/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/extracted-stig-library --dry-run
./dist/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/extracted-stig-library
```

The caller supplies the inventory root; no lab path is compiled in. Each scan's SSG XCCDF Benchmark ID selects its RHEL 7, 8, 9, or 10 family, and the library selects the newest eligible **extracted manual DISA XCCDF for that family** on each invocation. A library of ZIPs alone is insufficient. Place the appropriate [per-OS YAML template](BATCH-CKLB.md#per-os-checklist-tailoring) in that private library at mode 0600 to add administrator comments and checklist decisions. Use `--benchmark /private/official.xml` instead of `--library-root` only for a pinned, single-OS conversion. For a runnable archive that requires no Go toolchain on the disconnected host, see [disconnected release](DISCONNECTED-RELEASE.md).

Place `<prefix>.results.xml` or `<prefix>.results.xccdf.xml` in a directory whose basename equals the XCCDF target host. Same-prefix `<prefix>.report.html` enriches executed checks and item comparisons; `<prefix>.results.arf.xml` adds collected host values when HTML also exists. XCCDF-only results are accepted, but no unobserved values are invented. The application writes `-ASSESSMENT.cklb` plus a byte-bound `.cklb.provenance.json` beside each run in owner-private storage. It never silently overwrites changed output. Numeric V/SV mapping uses explicit newer SSG `V-…` or older SSG `SV-…` references; it is a mapping convention, not proof of semantic equivalence. Missing or ambiguous controls remain Not Reviewed unless an administrator explicitly tailors their checklist status. See [batch converter](BATCH-CKLB.md) for all input, permission, and output rules.

**Verification status:** The offline-built Linux/amd64 executable passed the Go suite and converted copied real XCCDF/HTML/ARF bundles from RHEL 7, 8, 9 and 10 using extracted official benchmarks and all four bundled YAML templates. A four-bundle dry run wrote nothing; conversion created four CKLB/provenance pairs; an unchanged rerun skipped all four. Independent readback checked the per-OS policy and checklist hashes, and the RHEL 9 passwordless-sudo admin decision remained distinguishable from its Open automated candidate. STIG Viewer GUI import has not been exercised by this CLI. See [batch converter](BATCH-CKLB.md) for historical output versions and limitations.

The legacy signed-release workflow is retired, not ported; the new per-OS YAML is a simpler checklist decision input, not a signature or release gate. **No signed-release, signature verification, or evidence-publication command exists here.** See the [Go workflow](WORKFLOW.md) and [asset contract](../contracts/asset-record-v1.md); a separate authorized process must handle signoff and delivery. Keep raw scans, approvals, generated checklists, keys, and host evidence private and out of Git; `.gitignore` is not a security boundary.
