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
- `baseline_sha256` and `pre_scan_sha256` are lowercase 64-character hexadecimal SHA-256 digests. `pre_scan_sha256` must equal the digest of the supplied `--pre` XML file's **bytes read for this check**. `lab_commit` is lowercase 40-character hexadecimal Git commit ID.

`stig-evidence asset-check --asset PATH --pre PATH --host FQDN` opens the two owner-private regular files without following final-component symlinks, reads each once, validates this record and the pre-scan digest, then returns without writing a snapshot or manifest. The fields describe **asserted upstream provenance**, not cryptographic attestation of baseline cleanliness, commit authenticity, the actual OS release, or that a guest was assessed. The retired signed-release workflow is not part of this Go repository; asset-check cannot authorize release or replace independently signed approvals and asset review.
