# Synthetic Cisco running-config and CKLB fixtures

These are **invented test inputs**, not exports from Cisco devices and **not compliance evidence**. They exercise IOS and IOS-XE routers/switches, an IOS-XR router, a NX-OS switch and an ASA firewall. Addresses use documentation-only ranges; any authentication strings are deliberately nonfunctional placeholders. The examples are intended to exercise benchmark pairing and STIG Viewer review, **not deployment on a device**. Platform-specific syntax is illustrative and has not been parser-validated on hardware.

**No example is asserted to be compliant.** The checked-in CKLBs under `checklists/` are historical unscored fixtures. Current `docket cisco-batch` builds a separate review package from `review-manifest.json`, each `scan.running-config`, and the switch `port-roles.csv` files. Pinned checks can mark Open, Not a Finding, or Not Applicable. Every control without a matching pin stays Not Reviewed. Rerunning does not overwrite the historical fixtures. Do not copy placeholder credentials into a real configuration.

## Layout

- `manifest.json`: exact device-to-benchmark associations, selected by an operator rather than guessed from config text.
- `targets/<host>/scan.running-config`: synthetic text; the target directory and config file need modes `0700` and `0600`, respectively, to run the converter. Git cannot retain those permissions on a fresh checkout; set them after checkout.
- `checklists/<exact-benchmark-id>/<host>/*.cklb`: one generated checklist per benchmark/host directory so Checkmate's newest-per-directory rule cannot hide a second benchmark for the same device.
- Each CKLB's `.provenance.json` binds hashes of the example config, official benchmark and CKLB. Its source paths are machine-specific generation records, **not portable attestations**. A copy in Checkmate contains the checkout path that generated it. An editor changes CKLB bytes and makes that sidecar's hash stale.

ISE, ACI and SNA benchmarks are not represented by invented IOS-style running configurations; their appliance/controller evidence models need separate fixtures. ASA IPS/VPN benchmarks likewise need those features explicitly configured and independently verified; the firewall/NDM examples do not assert IPS/VPN applicability.

## Reproduce from an owner-private benchmark library

This repository tracks 25 official manual XCCDF XMLs and 25 partial schema v3 root tailoring files under `stig-library-cisco/` (not in the generic archive). Alternatively obtain ZIPs through your approved DISA source and extract them with `cmd/checkmate/scripts/unpack-stig-library.sh`. In either case independently verify provenance, then stage authorized XML into an owner-owned `0700` private library. Manuals may be `0644`. Tailoring stays `0600`. The Git checkout's modes are not accepted by the converter. The generator below uses that private library. From the repository root:

```sh
umask 077
GOPROXY=off GOSUMDB=off go build -mod=vendor -o "$HOME/private/docket" ./cmd/docket
# Git does not preserve the required private modes on a fresh checkout:
chmod 700 examples/cisco-synthetic/targets/*
chmod 600 examples/cisco-synthetic/targets/*/scan.running-config
install -d -m 700 examples/cisco-synthetic/checklists
python3 scripts/generate-cisco-examples.py \
  --converter "$HOME/private/docket" \
  --library-root "$HOME/private/stig-library" \
  --source-root "$PWD/examples/cisco-synthetic" \
  --output-root "$PWD/examples/cisco-synthetic/checklists"
python3 tests/test-cisco-examples.py
```

The generator refuses unmarked configs, validates converter output hashes and exact benchmark IDs, stages each benchmark in a separate private directory, and never overwrites a different checklist. Keep operational benchmark copies, private scans and generated evidence out of Git; the tracked Cisco reference XML and partial tailoring files are the stated exception. For Checkmate inventory on a private copy of the generated checklists:

```sh
checkmate --root "$PWD/examples/cisco-synthetic/checklists" --list
checkmate --root "$PWD/examples/cisco-synthetic/checklists" --validate \
  --schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"
```

**Schema validity is not a successful STIG Viewer GUI import or a compliance score.**

`cisco-xccdf` can score these switch fixtures when the directory name matches the `hostname` command. The demo identity for FQDN, management IP, and a locally administered MAC is documented in [the admin walkthrough](../../docs/NETWORK-ADMIN-WALKTHROUGH.md).
