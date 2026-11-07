# Asset record v1

Supply `--asset PATH` as UTF-8 JSON with **exactly** these fields (no extras, omissions, or duplicate keys):

```json
{
  "schema_version": 1,
  "cycle_id": "2026-q4",
  "asset_fqdn": "node.example.test",
  "os_release": "rhel9.8",
  "role": "node",
  "baseline_state": "clean",
  "baseline_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "pre_scan_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "lab_commit": "cccccccccccccccccccccccccccccccccccccccc"
}
```

- `schema_version` is integer `1`, not Boolean. `cycle_id` is a nonempty ASCII identifier beginning with alphanumeric and followed by alphanumeric, `.`, `_` or `-`.
- `asset_fqdn` is a syntactically valid dot-separated FQDN and must equal `--host` byte-for-byte (case-sensitive). `os_release` is a nonempty string **copied from the producing manifest's `releases[].os_variant`**; this repository cannot independently look up that manifest.
- `role` is exactly `node`, `gui`, or `controller`. `baseline_state` is exactly `clean`.
- `baseline_sha256` and `pre_scan_sha256` are lowercase 64-character hexadecimal SHA-256 digests. `pre_scan_sha256` must equal the digest of the supplied `--pre` XML file's **snapshotted bytes**. `lab_commit` is lowercase 40-character hexadecimal Git commit ID.

The full asset JSON is snapshotted with the other inputs and copied to the private evidence directory. `manifest.json` includes its copy's hash under `inputs.asset.sha256` and binds it again at `metadata.asset_sha256`. These fields describe asserted upstream provenance, **not** cryptographic attestation of baseline cleanliness, commit authenticity, or the actual OS release. The record is not a substitute for signed approvals or independent asset review.
