# Synthetic Cisco running-config and CKLB fixtures

These are **invented test inputs**, not exports from Cisco devices and **not compliance evidence**. They exercise IOS and IOS-XE routers/switches, an IOS-XR router, a NX-OS switch and an ASA firewall. Addresses use documentation-only ranges; any authentication strings are deliberately nonfunctional placeholders. The examples are intended to exercise benchmark pairing and checklist review, **not deployment on a device**. Platform-specific syntax is illustrative and has not been parser-validated on hardware. One suspects the hardware would have opinions.

**No example is asserted to be 95% compliant.** The checked-in CKLBs are historical unscored converter fixtures; their sidecars record the earlier evaluator. The current separate `docket cisco-cklb` can decide the pinned IOS, IOS-XE, and NX-OS switch checks from a suitable saved config; every unsupported or ambiguous control stays `not_reviewed`. Its all-`auto` inventories do not override those decisions. A rerun creates a distinct versioned CKLB rather than rewriting the checked-in fixtures. Official Cisco checks also require operational state, external services, policy applicability, and topology that config text alone cannot prove. Review each official check and collect independent show-command/state evidence for the remainder. Do not copy placeholder credentials into a real configuration.

## Layout

- `manifest.json`: exact device-to-benchmark associations, selected by an operator rather than guessed from config text.
- `targets/<host>/scan.running-config`: synthetic text; the target directory and config file need modes `0700` and `0600`, respectively, to run the converter. Git cannot retain those permissions on a fresh checkout; set them after checkout.
- `checklists/<exact-benchmark-id>/<host>/*.cklb`: one generated checklist per benchmark/host directory so Checkmate's newest-per-directory rule cannot hide a second benchmark for the same device.
- Each CKLB's `.provenance.json` binds hashes of the example config, official benchmark and CKLB. Its source paths are machine-specific generation records, **not portable attestations**. A copy in Checkmate contains the original burden-of-proof source path. An editor changes CKLB bytes and makes that sidecar's hash stale.

These example configs, generated checklists and sidecars are **tracked in this checkout** even though CKLB patterns appear in `.gitignore`. Do not run the editor against the tracked `checklists/` tree. Copy it into an owner-private directory outside the repository first; Checkmate's `--root` must point at that copy. The generic binary archive contains none of this example tree or its guide.

ISE, ACI and SNA benchmarks are not represented by invented IOS-style running configurations; their appliance/controller evidence models need separate fixtures. ASA IPS/VPN benchmarks likewise need those features explicitly configured and independently verified; the firewall/NDM examples do not assert IPS/VPN applicability.

## Reproduce from an owner-private benchmark library

The separate, private `burden-of-proof` source checkout tracks 25 Cisco manual XCCDF XMLs and 25 complete all-`auto` inventories; the generic Checkmate and converter archives do **not** contain them. Alternatively obtain the ZIPs through your approved DISA source and extract them with this repository's source script. Stage an authorized, owner-private `0700` library with `0600` XML/policies before invoking the converter. The following commands assume the converter checkout is the current directory and copy only invented fixture inputs to a new private location outside either checkout:

```sh
umask 077
PRIVATE_FIXTURES="$HOME/private/checkmate-cisco-practice"  # choose a new path
# From the burden-of-proof checkout, not this one. This repository does not contain cmd/docket.
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -mod=vendor -o "$HOME/private/docket" ./cmd/docket
# Copy only the invented input fixtures, not the tracked generated checklists.
install -d -m 700 "$PRIVATE_FIXTURES"
cp -a examples/cisco-synthetic/manifest.json examples/cisco-synthetic/targets "$PRIVATE_FIXTURES/"
chmod 700 "$PRIVATE_FIXTURES/targets" "$PRIVATE_FIXTURES/targets"/*
chmod 600 "$PRIVATE_FIXTURES/manifest.json" "$PRIVATE_FIXTURES/targets"/*/scan.running-config
install -d -m 700 "$PRIVATE_FIXTURES/checklists"
python3 scripts/generate-cisco-examples.py \
  --converter "$HOME/private/docket" \
  --library-root "$HOME/private/stig-library-cisco" \
  --source-root "$PRIVATE_FIXTURES" \
  --output-root "$PRIVATE_FIXTURES/checklists"
```

The generator is owned by the separate converter repository; these commands are not an interface verified by Checkmate tests. Do not regenerate into tracked `checklists/` in this checkout. Official Cisco XML and actual device evidence must remain outside this fixture tree. For Checkmate inventory on your private copy, run `checkmate --root "$PRIVATE_FIXTURES/checklists" --list`. When that tree holds more than one benchmark, `--benchmark <stig_id>` opens the one you named instead of every newest checklist at once. Opt-in `checkmate --root "$PRIVATE_FIXTURES/checklists" --validate --schema /path/to/SV3_CKLB_1_0_JSON_SCHEMA.json` checks the JSON schema. **Schema validity is not a successful STIG Viewer GUI import or a compliance score.** The hardware would still have opinions. From that same private copy, `checkmate --root "$PRIVATE_FIXTURES/checklists" --benchmark <stig_id> --export-tailoring "$PRIVATE_FIXTURES/tailoring"` can draft a docket tailoring file for rows the selected hosts already answer the same way. These fixtures are not site policy. The draft's `rule_name` values are placeholders, not SCAP Security Guide names, and an explicit status in it would override the next conversion.
