# Layered Tailoring Guide

Docket supports **two-layer tailoring** for both RHEL and Cisco STIGs: a **root/site default** layer and a **per-host override** layer. This allows site-wide policy decisions while permitting host-specific exceptions.

## Overview

Tailoring files control how docket applies administrator decisions to scan results before generating checklists. The layered approach separates:

1. **Root layer**: Site-wide policy defaults (one file per benchmark at the library root)
2. **Host layer**: Host-specific overrides (same filename in the host's scan directory)

**Merge rule**: Root rules apply first, then host rules override on a per-control basis (keyed by `stig_id`/`sv_id`). A host file is optional; a host file with no root file is allowed.

## File Schema (Version 2)

All new tailoring files (root and host) use **schema version 2**:

```yaml
schema_version: 2
benchmark_id: RHEL_9_STIG           # or Cisco_IOS_Router_RTR_STIG, etc.
benchmark_sha256: <hex-digest>       # SHA-256 of the benchmark (fail closed on staleness)
rules:
  - stig_id: V-257837
    sv_id: SV-257837r1268251_rule
    rule_name: xwindows_remove_packages  # RHEL only (optional)
    status: not_a_finding               # or auto, open, not_applicable, not_reviewed
    comment: "Administrator decision justification here"
```

### Status Values
- **`auto`**: Retain the scan-derived status (no administrator override)
- **`open`**: Known finding
- **`not_a_finding`**: Verified compliant
- **`not_applicable`**: Control does not apply
- **`not_reviewed`**: Requires human review

### Comment Requirements
- **Root layer (schema v2)**: Non-`auto` overrides MUST have a comment. `auto` rows MUST NOT have comments (use status override with comment for policy decisions).
- **Root layer (schema v1/implicit, backward compat)**: Any comment allowed on `auto` rows (old RHEL templates).
- **Host layer**: ALL rows MUST have a comment, including `auto` (which documents why the root override is being reverted).

## RHEL Tailoring

### Root Layer (Site-Wide Policy)
- **Location**: `<library-root>/<benchmark-id>.tailoring.yaml` (e.g. `RHEL_9_STIG.tailoring.yaml`)
- **Scope**: Partial inventory (only the controls you want to override)
- **Purpose**: Site-wide decisions that apply to all RHEL hosts (e.g., "xwindows packages kept for graphical login")

**Example** (`RHEL_9_STIG.tailoring.yaml`):
```yaml
schema_version: 2
benchmark_id: RHEL_9_STIG
benchmark_sha256: a1b2c3d4...
rules:
  - rule_name: sudo_remove_nopasswd
    stig_id: V-258106
    sv_id: SV-258106r1102061_rule
    status: not_a_finding
    comment: "Passwordless sudo required for automation; documented and approved"
  
  - rule_name: mount_option_tmp_noexec
    stig_id: V-257867
    sv_id: SV-257867r958804_rule
    status: not_applicable
    comment: "Site requires execution from /tmp for legacy application support"
```

**Note**: In schema v2, `auto` entries have no comment. To document site context for rules you're NOT overriding, use documentation outside the tailoring file or create a commented template as reference.

### Host Layer (Per-Host Override)
- **Location**: `<scan-dir>/<benchmark-id>.tailoring.yaml` (beside the `.results.xccdf.xml`)
- **Scope**: Partial (only rules that differ from root)
- **Purpose**: Host-specific exceptions (e.g., "this particular host runs graphical desktop")

**Example** (`node42.example.test/RHEL_9_STIG.tailoring.yaml`):
```yaml
schema_version: 2
benchmark_id: RHEL_9_STIG
benchmark_sha256: a1b2c3d4...  # Must match current benchmark
rules:
  - stig_id: V-257837
    sv_id: SV-257837r1268251_rule
    status: auto
    comment: "Host runs headless; revert root override to use scan result"
```

### Commands That Apply Layered Tailoring

1. **`batch-cklb`**: Applies root + host tailoring for each discovered scan
   ```bash
   docket batch-cklb --input-root /scans --library-root /library
   ```

2. **`draft-cklb`**: Applies root + host tailoring for a single scan
   ```bash
   docket draft-cklb --scan node.results.xml --benchmark RHEL_9.xml --out node.cklb
   ```

3. **`reconcile`**: Produces reconciliation (no tailoring applied by default; `draft-cklb` applies tailoring)

## Cisco Tailoring

### Root Layer (Site-Wide Policy)
- **Location**: `<library-root>/<benchmark-id>.tailoring.yaml` (e.g. `Cisco_IOS_Router_RTR_STIG.tailoring.yaml`)
- **Scope**: **Full inventory required** (must list ALL controls from the benchmark, even if status is `auto`)
- **Purpose**: Site-wide defaults for all devices of this type

**Example** (`Cisco_IOS_Router_RTR_STIG.tailoring.yaml`):
```yaml
schema_version: 2
benchmark_id: Cisco_IOS_Router_RTR_STIG
benchmark_sha256: be7b76e01ac15525...
rules:
  - stig_id: V-216551
    sv_id: SV-216551r1137893_rule
    status: auto
  
  - stig_id: V-216555
    sv_id: SV-216555r1007824_rule
    status: not_applicable
    comment: "Site uses external AAA; local accounts not applicable"
  
  # ... ALL other controls (with auto or overrides)
```

### Host Layer (Per-Device Override)
- **Location**: `<device-dir>/<benchmark-id>.tailoring.yaml` (beside `scan.running-config`)
- **Scope**: Partial (only rules that differ from root)
- **Purpose**: Device-specific exceptions

**Example** (`sw1/<benchmark-id>.tailoring.yaml`):
```yaml
schema_version: 2
benchmark_id: Cisco_IOS_Router_RTR_STIG
benchmark_sha256: be7b76e01ac15525...
rules:
  - stig_id: V-216555
    sv_id: SV-216555r1007824_rule
    status: auto
    comment: "Device has local fallback accounts; revert root override"
```

### Commands That Apply Layered Tailoring

1. **`cisco-cklb`**: Single device checklist with layered tailoring
   ```bash
   docket cisco-cklb --config router1/scan.running-config --target router1 --benchmark Cisco_IOS_Router_RTR.xml
   ```

2. **`cisco-batch`**: Batch processing with layered tailoring
   ```bash
   docket cisco-batch --manifest devices.json --evidence-root /devices --library-root /library --output-root /output
   ```

3. **`cisco-xccdf`**: Scores config and writes XCCDF result, applying layered tailoring
   ```bash
   docket cisco-xccdf --config router1/scan.running-config --target router1 --benchmark Cisco_IOS_Router_RTR.xml --fqdn router1.example.test --ip 192.0.2.1 --mac 00:11:22:33:44:55 --role router --target-type Router --out router1/router1.results.xml
   ```

4. **`xccdf-cklb`**: Converts XCCDF result to checklist (tailoring already applied in the result)

## Validation Command

Use `docket tailoring check` to validate tailoring files before deployment:

```bash
# Check library root and scan tree
docket tailoring check --library-root /library --scan-root /scans

# Check single benchmark and host directory
docket tailoring check --benchmark RHEL_9.xml --scan-dir /scans/node42
```

The check command validates:
- Schema correctness (`schema_version`, `benchmark_id`, `benchmark_sha256`)
- Control ID matches (all `stig_id`/`sv_id` exist in the benchmark)
- Comment requirements (non-`auto` overrides have comments, host `auto` has comment)
- Full inventory requirement for Cisco root files
- Stale benchmark hashes (fails if `benchmark_sha256` doesn't match)

## Provenance Tracking

Layered tailoring provenance records:
- **Root file path and SHA-256** (`tailoring_root`)
- **Host file path and SHA-256** (`tailoring_host`)
- **Per-rule layer origin** (`tailoring_rule_layer`): maps each overridden `stig_id` to `"root"` or `"host"`

This appears in `.provenance.json` sidecars (schema version 2 for RHEL, schema version 4 for Cisco):

```json
{
  "schema_version": 2,
  "tailoring_root": {
    "path": "/library/RHEL_9_STIG.tailoring.yaml",
    "sha256": "abc123..."
  },
  "tailoring_host": {
    "path": "/scans/node42/RHEL_9_STIG.tailoring.yaml",
    "sha256": "def456..."
  },
  "tailoring_rule_layer": {
    "V-257837": "host",
    "V-258106": "root"
  }
}
```

## Backward Compatibility

### Old RHEL Templates (Schema v1 / Implicit)
Existing RHEL templates (`templates/RHEL_*_STIG.tailoring.yaml`) without `schema_version`, `benchmark_id`, or `benchmark_sha256` are accepted as **root files only**. These are treated as partial inventories with relaxed comment rules.

**Migration path**: Add `schema_version: 2`, `benchmark_id`, and `benchmark_sha256` to templates. This is recommended but not required immediately.

### Old Cisco Files (Schema v1)
Existing Cisco inventory files with `schema_version: 1` are accepted as **root files only** but must still be complete inventories. They are validated against the benchmark.

**Migration path**: Update `schema_version: 1` to `schema_version: 2` in all Cisco root files.

### Host Overrides
Host override files **must** use `schema_version: 2` with `benchmark_id` and `benchmark_sha256`. Old-format files are rejected for the host layer.

## Workflow Suggestions

### Initial Deployment

**For RHEL:**
1. Start from templates (old format) or create schema v2 root files with only site overrides
2. Deploy to library root
3. Run `docket tailoring check --library-root /library` to validate
4. Run `batch-cklb --dry-run` to verify behavior
5. Generate checklists

**For Cisco:**
1. Use `scripts/generate-cisco-tailoring.py --library-root /library` to create full-inventory root files (all `auto`)
2. Edit root files to add site-wide overrides (change `auto` to override + comment)
3. Run `docket tailoring check --library-root /library` to validate
4. Run `cisco-batch --dry-run` to verify behavior
5. Generate checklists

### Host-Specific Exception
1. Run batch processing (generates suggested tailoring worksheets beside each checklist)
2. Review `.tailoring.yaml` worksheet beside each generated checklist
3. Edit worksheet: keep only rules that differ from root, ensure all rows have comments
4. Copy edited worksheet to host directory (RHEL: beside `.results.xccdf.xml`; Cisco: beside `scan.running-config`)
5. Re-run batch processing; host overrides now apply
6. Run `docket tailoring check --scan-root /scans` to validate host files

### Updating Policy After Benchmark Update
1. Update benchmark files in library
2. Update `benchmark_sha256` in all tailoring files (root and host)
3. Run `docket tailoring check` to detect stale hashes
4. Fix any mismatched control IDs (new/removed controls)
5. Re-run conversions

## Disconnected Deployment

The `scripts/package-disconnected.sh` script includes:
- **RHEL templates** (4): Schema v1/implicit format, in `templates/` directory
- **Cisco root inventories** (25): Schema v2 full inventories, in `cisco-library/` directory
- **Cisco tailoring generator**: `scripts/generate-cisco-tailoring.py` for creating additional root files
- **Documentation**: Including `docs/TAILORING.md`

After unpacking the release archive:
1. **RHEL**: RHEL templates are examples. Copy to library root and edit for site policy, or create new schema v2 files.
2. **Cisco**: Cisco root inventories are in `cisco-library/`. Copy to your library root (beside benchmarks). All are `auto` by default; edit to add site overrides.
3. **Validation**: Run `docket tailoring check --library-root /library` before first use.

The package does NOT include: official DISA benchmarks, private scans, device configs, or site-specific tailoring edits.

## Troubleshooting

### "benchmark_sha256 mismatch"
The tailoring file pins an old benchmark version. Update the hash or regenerate the tailoring file.

### "incomplete control inventory (expected N, got M)"
Cisco root files must list ALL controls. Ensure the file has one entry per control in the benchmark.

### "comment required for all host overrides"
Host files must have comments on every row, including `auto` (which explains why the root override is being reverted).

### "host override files must use schema_version 2"
Old-format files are not allowed for host overrides. Use schema version 2 with `benchmark_id` and `benchmark_sha256`.

### Tailoring file ignored
- Check file is owner-private (`0600`) regular file (no symlinks)
- Verify filename matches `<benchmark-id>.tailoring.yaml` exactly
- For RHEL: file must be in library root or host scan directory
- For Cisco: file must be in library root or device directory (beside `scan.running-config`)

### Worksheet drops applied overrides
This was a known issue with `cisco-batch` before the layered system. Now fixed: worksheets preserve existing host overrides and show only rules that differ from root.

## Examples

See:
- `templates/RHEL_*.tailoring.yaml` for RHEL root templates (old schema, still supported)
- `stig-library-cisco/*.tailoring.yaml` for Cisco root inventories (currently schema v1, will be migrated to v2)

For host-layer examples, run `cisco-batch` or `batch-cklb` with `--dry-run` and review the generated `.tailoring.yaml` worksheets.
