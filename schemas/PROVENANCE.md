# DISA CKLB 1.0 JSON schema provenance

- Source: [DISA Cyber Exchange STIG Viewer 3 tools](https://public.cyber.mil/stigs/srg-stig-tools/); downloaded from `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/SV3_CKLB_1_0_JSON_SCHEMA.zip`.
- Archive member: `SV3_CKLB_1_0_JSON_SCHEMA.json` (unmodified, 12,032 bytes).
- Extracted JSON SHA-256: `8b88205de07662006e1660b1decad677d344828d6687b1dd26bca15105b7bb37`.
- JSON Schema draft: 2019-09; CKLB format: STIG Viewer 3 checklist 1.0.

The upstream ZIP contains only the JSON file and no license or redistribution notice. This file is third-party DISA material, **not covered by this repository's license**. Its presence in this private repository does not establish permission to redistribute it publicly. Confirm the applicable terms with your organization before distributing a release beyond authorized recipients. A SHA-256 comparison verifies byte identity, not publisher authentication; obtain the expected value through an independently trusted channel.

The converter does not use this schema to create CKLBs. `checkmate --validate --schema schemas/SV3_CKLB_1_0_JSON_SCHEMA.json` checks existing checklists, and the Bash preflight can pass that same schema through. `checkmate` is `cmd/checkmate` in this module.

## Assessment provenance schema versions

The `.cklb.provenance.json` sidecars use these schema versions:

- **Schema v1**: Initial provenance with single tailoring file
- **Schema v2**: Layered RHEL tailoring (root + host files with per-rule layer attribution)
- **Schema v3**: Cisco single-layer tailoring
- **Schema v4**: Layered Cisco tailoring (root + host files with per-rule layer attribution)

Schema v2 and v4 provenance sidecars include:
- `tailoring_root`: Root layer file path and SHA-256
- `tailoring_host`: Host layer file path and SHA-256 (when present)
- `tailoring_rule_layer`: Per-rule origin map showing which layer defined each tailored rule

See [TAILORING.md](../docs/TAILORING.md) for layered tailoring documentation.
