# Synthetic Cisco running-config and CKLB fixtures

These are **invented test inputs**, not exports from Cisco devices and **not compliance evidence**. They exercise IOS and IOS-XE routers/switches, an IOS-XR router, a NX-OS switch and an ASA firewall. Addresses use documentation-only ranges; any authentication strings are deliberately nonfunctional placeholders. The examples are intended to exercise benchmark pairing and checklist review, **not deployment on a device**. Platform-specific syntax is illustrative and has not been parser-validated on hardware. One suspects the hardware would have opinions.

**No example is asserted to be compliant.** The checked-in CKLBs are historical unscored fixtures. `docket cisco-cklb` can decide the pinned IOS, IOS-XE, and NX-OS switch checks from a suitable saved config; every unsupported or ambiguous control stays `not_reviewed`. A partial schema v3 tailoring file does not override the controls it omits. A rerun creates a distinct versioned CKLB rather than rewriting the checked-in fixtures. Official Cisco checks also require operational state, external services, policy applicability, and topology that config text alone cannot prove. Review each official check and collect independent show-command evidence for the remainder. Do not copy placeholder credentials into a real configuration.

## Layout

- `manifest.json`: exact device-to-benchmark associations, selected by an operator rather than guessed from config text.
- `targets/<host>/scan.running-config`: synthetic text; the target directory and config file need modes `0700` and `0600`, respectively, to run the converter. Git cannot retain those permissions on a fresh checkout; set them after checkout.
- `checklists/<exact-benchmark-id>/<host>/*.cklb`: one generated checklist per benchmark/host directory so Checkmate's newest-per-directory rule cannot hide a second benchmark for the same device.
- Each CKLB's `.provenance.json` binds hashes of the example config, official benchmark and CKLB. Its source paths are machine-specific generation records, **not portable attestations**. A copy in Checkmate contains the original burden-of-proof source path. An editor changes CKLB bytes and makes that sidecar's hash stale.

These example configs, generated checklists and sidecars are **tracked in this checkout** even though CKLB patterns appear in `.gitignore`. Do not run the editor against the tracked `checklists/` tree. Copy it into an owner-private directory outside the repository first; Checkmate's `--root` must point at that copy. The generic binary archive contains none of this example tree or its guide.

ISE, ACI and SNA benchmarks are not represented by invented IOS-style running configurations; their appliance/controller evidence models need separate fixtures. ASA IPS/VPN benchmarks likewise need those features explicitly configured and independently verified; the firewall/NDM examples do not assert IPS/VPN applicability.

## Reproduce from an owner-private benchmark library

This repository tracks 25 Cisco manual XCCDF XMLs and 25 partial schema v3 root files under `stig-library-cisco/`. The runtime archive does not contain them. Alternatively obtain the ZIPs through your approved DISA source and extract them with `cmd/checkmate/scripts/unpack-stig-library.sh`. Stage an authorized, owner-private `0700` library before invoking the converter. Manuals may be `0644`. Tailoring stays `0600`. From the repository root:

```sh
umask 077
PRIVATE_FIXTURES="$HOME/private/checkmate-cisco-practice"
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -mod=vendor -o "$HOME/private/docket" ./cmd/docket
install -d -m 700 "$PRIVATE_FIXTURES"
cp -a cmd/checkmate/examples/cisco-synthetic/manifest.json cmd/checkmate/examples/cisco-synthetic/targets "$PRIVATE_FIXTURES/"
chmod 700 "$PRIVATE_FIXTURES" "$PRIVATE_FIXTURES/targets" "$PRIVATE_FIXTURES/targets"/*
chmod 600 "$PRIVATE_FIXTURES/manifest.json" "$PRIVATE_FIXTURES/targets"/*/scan.running-config
install -d -m 700 "$PRIVATE_FIXTURES/checklists"
python3 scripts/generate-cisco-examples.py \
  --converter "$HOME/private/docket" \
  --library-root "$HOME/private/stig-library-cisco" \
  --source-root "$PRIVATE_FIXTURES" \
  --output-root "$PRIVATE_FIXTURES/checklists"
checkmate --root "$PRIVATE_FIXTURES/checklists" --list
checkmate --root "$PRIVATE_FIXTURES/checklists" --validate \
  --schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"
checkmate --root "$PRIVATE_FIXTURES/checklists" \
  --benchmark Cisco_IOS_XE_Switch_L2S_STIG \
  --export-tailoring "$PRIVATE_FIXTURES/tailoring"
```

Do not regenerate into the tracked `checklists/` tree. Official Cisco XML and actual device evidence stay outside this fixture tree. **Schema validity is not a successful STIG Viewer GUI import or a compliance score.** The export is schema v3 and does not invent `rule_name`. An explicit status in it overrides the next conversion. These fixtures are not site policy.
