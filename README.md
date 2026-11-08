# Burden of Proof

An offline Go toolkit for turning saved OpenSCAP SSG results into **private CKLB review candidates** and byte-bound provenance. This repository owns the review-conversion policy, reconciliation, CKLB generation, and evidence-side checks. It does **not** provision the lab or run a scan. The lab lives in a separate repository and supplies a versioned, non-secret [asset record](contracts/asset-record-v1.md) for the `asset-check` handoff. The boundary is intentional; a checksum is not a character reference for the guest.

## Start here

| Need | Read |
| --- | --- |
| Build, convert, and understand the current verification boundary | [Quick start](docs/README.md) |
| Recursive input pairing, benchmark selection, output and provenance rules | [Batch CKLB converter](docs/BATCH-CKLB.md) |
| CLI commands and retired implementation scope | [Go-only converter](docs/GO-MIGRATION.md) |
| Operational review and external verification | [Workflow](docs/WORKFLOW.md) |
| Lab-to-evidence v1 handoff fields and limitations | [Asset record contract](contracts/asset-record-v1.md) |

## What the output means

The converter joins explicit SSG `V-…` or historical `SV-…` references to official DISA manual XCCDF controls by numeric ID. That produces **candidate** statuses, not an official DISA scan or proof that the SSG and DISA checks have equivalent semantics. Missing or ambiguous controls remain Not Reviewed. Generated CKLB files and their provenance sidecars are review artifacts: their hashes bind bytes, but neither a hash nor an asset record attests guest state, operator approval, or scan authenticity.

There is no signed-release, signature-verification, or evidence-publication command here. Schema validation, human review, STIG Viewer import, approval, and delivery require separate authorized steps. Keep scans, benchmarks, generated checklists, sidecars, approvals, and keys in owner-private storage outside Git. `.gitignore` is housekeeping, not access control.
