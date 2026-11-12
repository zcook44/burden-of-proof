# Synthetic Cisco running-config and CKLB fixtures

These are **invented test inputs**, not exports from Cisco devices and **not compliance evidence**. They exercise IOS and IOS-XE routers/switches, an IOS-XR router, a NX-OS switch and an ASA firewall. Addresses use documentation-only ranges; any authentication strings are deliberately nonfunctional placeholders. The examples are intended to exercise benchmark pairing and STIG Viewer review, **not deployment on a device**. Platform-specific syntax is illustrative and has not been parser-validated on hardware.

**No example is asserted to be 95% compliant.** The checked-in CKLBs here are historical **unscored converter fixtures** generated before the bounded native L2S evaluator; their provenance records that earlier converter version. Current `stig-evidence cisco-cklb` evaluates only the explicitly implemented IOS-XE Switch L2S V3R2 global STP checks (`V-220657`, `V-220664`) and leaves every unsupported or ambiguous control `not_reviewed`. Rerunning the current converter creates a separate versioned output; it does not overwrite these older examples. Official Cisco checks also include operational state, external services, topology and applicability a saved running configuration cannot prove. Review each official check and collect independent show-command/state evidence for remaining controls. Do not copy placeholder credentials into a real configuration.

## Layout

- `manifest.json`: exact device-to-benchmark associations, selected by an operator rather than guessed from config text.
- `targets/<host>/scan.running-config`: synthetic text; the target directory and config file need modes `0700` and `0600`, respectively, to run the converter. Git cannot retain those permissions on a fresh checkout; set them after checkout.
- `checklists/<exact-benchmark-id>/<host>/*.cklb`: one generated checklist per benchmark/host directory so Checkmate's newest-per-directory rule cannot hide a second benchmark for the same device.
- Each CKLB's `.provenance.json` binds hashes of the example config, official benchmark and CKLB. Its source paths are machine-specific generation records, **not portable attestations**. A copy in Checkmate contains the original burden-of-proof source path. An editor changes CKLB bytes and makes that sidecar's hash stale.

ISE, ACI and SNA benchmarks are not represented by invented IOS-style running configurations; their appliance/controller evidence models need separate fixtures. ASA IPS/VPN benchmarks likewise need those features explicitly configured and independently verified; the firewall/NDM examples do not assert IPS/VPN applicability.

## Reproduce from an owner-private benchmark library

The official manual XCCDF XMLs are **not included** in either repository. Obtain the ZIPs through your approved DISA source, then extract them with the Checkmate source script into a new private library. From the `burden-of-proof` root:

```sh
umask 077
GOPROXY=off GOSUMDB=off go build -mod=vendor -o "$HOME/private/stig-evidence" ./cmd/stig-evidence
# Git does not preserve the required private modes on a fresh checkout:
chmod 700 examples/cisco-synthetic/targets/*
chmod 600 examples/cisco-synthetic/targets/*/scan.running-config
install -d -m 700 examples/cisco-synthetic/checklists
python3 scripts/generate-cisco-examples.py \
  --converter "$HOME/private/stig-evidence" \
  --library-root "$HOME/private/stig-library" \
  --source-root "$PWD/examples/cisco-synthetic" \
  --output-root "$PWD/examples/cisco-synthetic/checklists"
python3 tests/test-cisco-examples.py
```

The generator refuses unmarked configs, validates converter output hashes and exact benchmark IDs, stages each benchmark in a separate private directory, and never overwrites a different checklist. All official benchmark XML and private scan material remain outside Git. For Checkmate inventory, run its executable with `--root /path/to/checkmate/examples/cisco-synthetic/checklists --list`; opt-in `--validate --schema /path/to/checkmate/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json` checks the JSON schema. **Schema validity is not a successful STIG Viewer GUI import or a compliance score.**
