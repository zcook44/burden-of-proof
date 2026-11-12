# Quick start: private review conversion

Burden of Proof owns the evidence-side policy and review conversion: it checks a versioned, non-secret [lab asset record](../contracts/asset-record-v1.md), reconciles saved SSG results against official manual XCCDF controls, and evaluates only a **small pinned subset** of [Cisco running-config checks](CISCO-CONFIG.md) from an explicitly selected benchmark. Unimplemented Cisco controls remain Not Reviewed. The lab and its provisioning/scanning live in a separate repository. No lab path is compiled into this CLI, and conversion does not attest the lab's assertions. The CLI does not collect device configs, run scans, sign off findings, or deliver evidence. It knows precisely where its remit ends; an unusual trait for software.

[Repository overview](../README.md) · [Batch rules](BATCH-CKLB.md) · [Cisco config candidates](CISCO-CONFIG.md) · [Commands and scope](GO-MIGRATION.md) · [Review workflow](WORKFLOW.md) · [Lab scan command and playbook snapshot](OSCAP-SOURCE.md) · [Disconnected release](DISCONNECTED-RELEASE.md)

## Build and convert

From the repository root on Linux with Go 1.22+ (vendored dependency; no runtime network access):

```sh
install -d -m 700 dist
GOPROXY=off GOSUMDB=off go build -mod=vendor -o dist/stig-evidence ./cmd/stig-evidence
./dist/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/extracted-stig-library --dry-run
./dist/stig-evidence batch-cklb --input-root /private/inventory --library-root /private/extracted-stig-library
```

The caller supplies the inventory root; no lab path is compiled in. Each scan's SSG XCCDF Benchmark ID selects its RHEL 7, 8, 9, or 10 family, and the library selects the newest eligible **extracted manual DISA XCCDF for that family** on each invocation. A library of ZIPs alone is insufficient. An optional [per-OS YAML](BATCH-CKLB.md#per-os-checklist-tailoring) in that private library at mode 0600 adds administrator comments and decisions. **Do not copy the packaged examples into an operational library as approved policy**: the RHEL 9 example includes a lab-specific `not_a_finding` override. Review and authorize every status/comment for all hosts of that OS, or omit the policy. Use `--benchmark /private/official.xml` instead of `--library-root` only for a pinned, single-OS conversion. For the offline archive and initial-deployment Bash preflight, see [disconnected release](DISCONNECTED-RELEASE.md).

Place `<prefix>.results.xml` or `<prefix>.results.xccdf.xml` in a directory whose basename equals the XCCDF target host. Same-prefix `<prefix>.report.html` enriches executed checks and item comparisons; `<prefix>.results.arf.xml` adds collected host values when HTML also exists. XCCDF-only results are accepted, but no unobserved values are invented. The application writes `-ASSESSMENT.cklb` plus a byte-bound `.cklb.provenance.json` beside each run in owner-private storage. It never silently overwrites changed output. Numeric V/SV mapping uses explicit newer SSG `V-…` or older SSG `SV-…` references; it is a mapping convention, not proof of semantic equivalence. Missing or ambiguous controls remain Not Reviewed unless an administrator explicitly tailors their checklist status. See [batch converter](BATCH-CKLB.md) for all input, permission, and output rules.

**Verification status:** The offline-built Linux/amd64 executable passed the Go suite and converted copied real XCCDF/HTML/ARF bundles from RHEL 7, 8, 9 and 10 using extracted official benchmarks and all four bundled YAML templates. A four-bundle dry run wrote nothing; conversion created four CKLB/provenance pairs; an unchanged rerun skipped all four. Independent readback checked the per-OS policy and checklist hashes, and the RHEL 9 passwordless-sudo admin decision remained distinguishable from its Open automated candidate. STIG Viewer GUI import has not been exercised by this CLI. See [batch converter](BATCH-CKLB.md) for historical output versions and limitations.

## Cisco: stage a private library, then select the benchmark

This private source checkout includes 25 Cisco manual XCCDF files and 25 complete all-`auto` tailoring inventories under `stig-library-cisco/`. Git checkout permissions do **not** meet the CLI's private-input contract. Stage owner-private copies first; the generic offline archive does not ship these inputs. Replace `/private/...` with paths you own and control before running the example. Choose a **new, absent** library destination: repeating the `install` commands over an administrator-edited policy would erase that decision.

```sh
install -d -m 700 "$HOME/private"
LIB="$HOME/private/stig-library-cisco-new"  # choose a destination that does not exist
[ ! -e "$LIB" ] || { printf 'Library already exists: %s\n' "$LIB" >&2; exit 1; }
install -d -m 700 "$LIB"
install -m 600 stig-library-cisco/*.xml "$LIB/"
install -m 600 stig-library-cisco/*.tailoring.yaml "$LIB/"
./dist/stig-evidence cisco-cklb \
  --config /private/configs/switch1.example.test/scan.running-config \
  --target switch1.example.test \
  --library-root "$LIB" \
  --benchmark-id Cisco_IOS_XE_Switch_L2S_STIG \
  --dry-run
# Confirm the exact device platform and role, then omit --dry-run to write.
```

The config itself must be owner-private `0600` in a `0700` directory named exactly for the target. `cisco-cklb` currently automates two pinned IOS-XE Switch L2S V3R2 global STP checks; the remaining controls require review. The complete policies leave results alone until an administrator changes a status **and** supplies a comment. A status override affects every target using that benchmark/library, so a host-specific exception needs its own private library. [Cisco rules and evidence boundary](CISCO-CONFIG.md). The Bash `preflight-offline.sh` checks RHEL `batch-cklb` inputs; it is not a Cisco preflight.

The legacy signed-release workflow is retired, not ported; the new per-OS YAML is a simpler checklist decision input, not a signature or release gate. **No signed-release, signature verification, or evidence-publication command exists here.** The separate Checkmate tool can inventory, optionally validate, or edit existing CKLBs; it does not convert scans or approve findings, and editing leaves the converter's provenance hash stale. See the [Go workflow](WORKFLOW.md) and [asset contract](../contracts/asset-record-v1.md); a separate authorized process must handle signoff and delivery. Keep raw scans, approvals, generated checklists, keys, and host evidence private and out of Git; `.gitignore` is not a security boundary.
