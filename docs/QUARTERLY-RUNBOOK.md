# Quarterly STIG runbook

This is the operator procedure for one DISA publication quarter on a disconnected network. It uses the Ceasefire archive: the `docket` and `checkmate` binaries, the shared config file, and `docket quarter`.

`docket` does not download manuals, scan a host, log into a switch, or approve a finding. You move the manuals and the evidence. The tools write private checklists. A person reviews them.

Read [CONFIG.md](CONFIG.md) and [TAILORING.md](TAILORING.md) once. This runbook is the sequence.

## What you have at the end

- One library that contains this quarter's manuals and root tailoring pinned to those bytes.
- A fresh OpenSCAP result for every in-scope RHEL host.
- A fresh running configuration for every in-scope Cisco device.
- One CKLB per host and benchmark, written so STIG Viewer can show the check, the discussion, the fix, the potential impact, and this host's finding.
- Last quarter's library, scans, configs, and checklists outside the active paths.

## Layout

Use these paths, or the same names in `~/.config/docket/config.yaml`. No symlinks.

## Directory permissions

Every directory the tools walk is mode `0700` and owned by the account that runs `docket`. `install -d -m 700 a/b` sets `0700` on `b` only. The parent `a` can stay `0755`, and the tools then refuse the tree. Set the mode on each directory, including parents.

```sh
install -d -m 700 \
  /private \
  /private/stig-library \
  /private/stig-archive \
  /private/stig-archive/2026-q3 \
  /private/inventory \
  /private/inventory/2026-q4 \
  /private/evidence \
  /private/cisco-review \
  /private/cisco-review/2026-q4 \
  /private/checklists \
  /private/checklists/2026-q4 \
  "$HOME/.config" \
  "$HOME/.config/docket"
chmod 700 /private /private/stig-library /private/stig-archive /private/stig-archive/2026-q3 \
  /private/inventory /private/inventory/2026-q4 \
  /private/evidence /private/cisco-review /private/cisco-review/2026-q4 \
  /private/checklists /private/checklists/2026-q4
```

The library root and every subdirectory under it, including a drop directory such as `/private/stig-library/drop`, are `0700`. A new host directory under the inventory and a new device directory under the evidence root are `0700` as well. After those directories exist:

```sh
find /private/stig-library /private/inventory /private/evidence \
  /private/cisco-review /private/checklists /private/stig-archive \
  -type d -exec chmod 700 {} +
chown -R "$(id -un)":"$(id -gn)" /private/stig-library /private/inventory /private/evidence \
  /private/cisco-review /private/checklists /private/stig-archive
```

`chown` is for a copy that left another account as the owner. Skip it when `id -un` already owns the tree.

A manual whose name ends in `_Manual-xccdf.xml` may be mode `0644`. It must not be group-writable, world-writable, or executable. Tailoring files, scans, device configs, the manifest, and checklists are mode `0600`.

```sh
find /private/stig-library -type d -exec chmod 700 {} +
find /private/stig-library -name '*_Manual-xccdf.xml' -exec chmod 644 {} +
find /private/stig-library -name '*.tailoring.yaml' -exec chmod 600 {} +
find /private/inventory /private/evidence -type f -exec chmod 600 {} +
chmod 600 /private/evidence/devices.json "$HOME/.config/docket/config.yaml"
```

| Path | Contents this quarter |
| --- | --- |
| `/private/stig-library` | This quarter's manuals and `<benchmark-id>.tailoring.yaml` root files |
| `/private/stig-archive/2026-q3` | Last quarter's library, moved out before the new manuals go live |
| `/private/inventory/2026-q4` | This quarter's RHEL scan tree only |
| `/private/evidence` | `<host>/scan.running-config` and optional `port-roles.csv` |
| `/private/evidence/devices.json` | Cisco batch manifest |
| `/private/cisco-review/2026-q4` | `cisco-batch` output |
| `/private/checklists/2026-q4` | Optional working copies for checkmate. Security imports the CKLBs `docket quarter` wrote. |

`batch-cklb` and the Cisco commands walk subdirectories of the library and take the highest version, then the highest release. `tailoring check` uses that same rule. A newer manual left under `old/` becomes the benchmark for every host. Archive last quarter **outside** the library root.

## 0. Install the bundle

The connected build machine needs Go 1.22 or newer on `PATH`. Go 1.22.2 and Go 1.27.3 are both enough. `go.mod` says `go 1.22.0`. `scripts/package-disconnected.sh` sets `GOTOOLCHAIN=local` and `GOPROXY=off`, so it uses that compiler and does not download one. If the compiler is missing or older than 1.22, the script stops before `go test` and prints the tarball install. Copy `go1.22.2.linux-amd64.tar.gz` from a connected machine, then:

```sh
rm -rf "$HOME/sdk/go"
mkdir -p "$HOME/sdk"
tar -C "$HOME/sdk" -xzf go1.22.2.linux-amd64.tar.gz
export PATH="$HOME/sdk/go/bin:$PATH"
go version
./scripts/package-disconnected.sh 2.1.0 ./dist/releases
sha256sum ./dist/releases/ceasefire-2.1.0-linux-amd64.tar.gz
```

The disconnected host that only runs the installed binaries does not need Go.

Transfer `ceasefire-2.1.0-linux-amd64.tar.gz` and the `.sha256` file beside it. On the disconnected host:

```sh
cd /secure/incoming
sha256sum -c ceasefire-2.1.0-linux-amd64.tar.gz.sha256
./scripts/install-docket.sh --prefix "$HOME/.local" /secure/incoming/ceasefire-2.1.0-linux-amd64.tar.gz
```

The installer unpacks the archive, checks the checksum, and installs `docket` and `checkmate`. Expected lines when the system completion directory is not writable:

```text
INSTALLED /home/<you>/.local/bin/docket
INSTALLED /home/<you>/.local/bin/checkmate
COMPLETION /home/<you>/.local/share/bash-completion/completions/docket
```

A writable system directory prints `COMPLETION /usr/share/bash-completion/completions/docket` instead. The prefix copies are always installed at `$prefix/share/bash-completion/completions/`. If `$prefix/bin` is not on `PATH`, the installer still exits 0 and prints the line to add:

```text
install-docket: /home/<you>/.local/bin is not on PATH.
install-docket: add it for this account with:
  export PATH="/home/<you>/.local/bin:$PATH"
```

Open a new shell after that line, or call the binaries by the paths in the `INSTALLED` lines. Confirm the commands exist:

```sh
docket quarter --help
docket tailoring rehash --help
checkmate --help
```

`docket quarter --help` and `docket tailoring rehash --help` print usage and exit 0. `checkmate` with no flags prints usage and exits 2; that is the flag parser, not a failed install.

## 1. Write the config

```sh
install -d -m 700 "$HOME/.config/docket"
cat > "$HOME/.config/docket/config.yaml" <<'EOF'
library_root: /private/stig-library
input_root: /private/inventory/2026-q4
evidence_root: /private/evidence
cisco_manifest: /private/evidence/devices.json
output_root: /private/cisco-review/2026-q4
checklist_root: /private/checklists/2026-q4
EOF
chmod 600 "$HOME/.config/docket/config.yaml"
```

Flags override this file. `DOCKET_LIBRARY_ROOT` and the other `DOCKET_*` variables override the file and lose to flags. See [CONFIG.md](CONFIG.md).

## 2. Stage the new manuals (connected machine)

Obtain the official DISA **manual** XCCDF through the channel you already trust. The SSG datastream on a RHEL guest is the scan content. It does not go in the library.

Expected names:

| Family | Filename |
| --- | --- |
| RHEL | `U_RHEL_<major>_STIG_V<version>R<release>_Manual-xccdf.xml` |
| Cisco | `U_Cisco_..._V<version>R<release>_Manual-xccdf.xml` or the `STIG_Manual` form |

```sh
install -d -m 700 /private/stig-stage
# copy only the Manual-xccdf.xml files into that directory
sha256sum /private/stig-stage/*.xml | tee /private/stig-stage/SHA256SUMS
```

Transfer the directory and `SHA256SUMS`. On the disconnected host:

```sh
(cd /private/stig-stage && sha256sum -c SHA256SUMS)
```

A mismatch stops the quarter. Do not copy the files into the live library until this check passes.

## 3. Swap the library

```sh
install -d -m 700 /private/stig-archive
mv /private/stig-library /private/stig-archive/2026-q3
install -d -m 700 /private/stig-library
cp -a /private/stig-stage/*.xml /private/stig-library/
# root tailoring comes from last quarter, then the pin is rewritten
cp -a /private/stig-archive/2026-q3/*.tailoring.yaml /private/stig-library/ || true
```

Manuals may stay mode `0644`. Tailoring files must be mode `0600`:

```sh
chmod 600 /private/stig-library/*.tailoring.yaml
```

## Tailoring schema, in plain words

The tools read a tailoring file only when `schema_version` is `3`. That number is the tailoring format. It is not the Cisco manifest number and it is not the provenance sidecar number.

- A version 3 root file lives at the library root and is named `<benchmark-id>.tailoring.yaml`. It lists only the rules an administrator decided. `benchmark_sha256` is the SHA-256 of the manual those rules were written against.
- A version 3 host file has the same name in that host's directory. It has no hash. It overrides the root file for that host.
- A file with no `schema_version`, or with version 1 or 2, is an older inventory. Conversion refuses it. `docket tailoring migrate` rewrites it once: comment-less `auto` rows are dropped, a host hash is removed, and the file becomes version 3. A root pin that is already 64 hex digits is kept. Any other pin becomes `rehash-me`.
- Run migrate when `tailoring check` says the schema is not current, and when you copied last quarter's tailoring forward and those files predate version 3. You do not run it again on files that are already version 3.
- `devices.json` uses `schema_version: 1` because it is a device list. Do not migrate it.
- A `.cklb.provenance.json` sidecar is written by `docket`. Untailored RHEL sidecars are version 1. Layered RHEL sidecars and untailored Cisco sidecars are version 2. Layered Cisco sidecars are version 4. Do not migrate them and do not edit them by hand.

```sh
docket tailoring migrate --library-root /private/stig-library --dry-run
docket tailoring migrate --library-root /private/stig-library
```

Expected output names each file `MIGRATE` or `UNCHANGED`, then `MIGRATE files=N`. Host files are not in the library root. Migrate those with `--scan-root` when an old host file is still in the inventory.

Pin the root files to the manuals just copied:

```sh
docket tailoring rehash --dry-run
```

Expected:

```text
REHASH /private/stig-library/RHEL_9_STIG.tailoring.yaml -> <64 hex> (/private/stig-library/U_RHEL_9_STIG_V2R11_Manual-xccdf.xml)
DRY RUN rehash changed=N unchanged=M
```

The dry run does not change the files. Confirm each path is this quarter's manual, not a file under the archive. Then:

```sh
docket tailoring rehash
docket tailoring check
```

`tailoring check` with no flags uses `library_root` and `input_root` from the config. Before scans exist, point it at the library only:

```sh
docket tailoring check --library-root /private/stig-library
```

Expected:

```text
Checking library root: /private/stig-library
OK: RHEL_9_STIG.tailoring.yaml (root layer, /private/stig-library/U_RHEL_9_STIG_V2R11_Manual-xccdf.xml)
OK: Cisco_IOS_XE_Switch_L2S_STIG.tailoring.yaml (root layer, /private/stig-library/...)

VALIDATION PASSED: no issues, 0 warnings
```

### When rehash or check fails

| Message | What to do |
| --- | --- |
| `schema_version … is not current` | Run `docket tailoring migrate`, then rehash. |
| `no benchmark for exact ID` or `no extracted RHEL` | The manual is missing, misnamed, or not under the library. Do not point the library at the archive. |
| `ambiguous benchmark` | Two files share a version and release. Remove one. |
| `benchmark_sha256 mismatch` | Rehash was not run, or a newer manual arrived after rehash. Run rehash again and read the path it prints. |
| `unknown or mismatched STIG/SV ID` | A rule's `sv_id` is from last quarter's manual. Update that row or delete it. Do not keep a stale rule id. |
| `comment required` | A non-`auto` row, or a host `auto` row, has no comment. Add the reason or delete the row. |

## 4. Collect RHEL evidence

On each RHEL host, run the authorized OpenSCAP scan with the SSG content for that major. Fetch the result into a tree that contains this quarter only:

```text
/private/inventory/2026-q4/<fqdn>/<prefix>.results.xml
```

Optional same-prefix `.report.html` and `.results.arf.xml` add observations. The directory and the files are owner-private. The target in the results must be that host.

A host exception, if you already know it, is a partial file with no hash:

```sh
install -d -m 700 /private/inventory/2026-q4/node42.example.test
cat > /private/inventory/2026-q4/node42.example.test/RHEL_9_STIG.tailoring.yaml <<'EOF'
schema_version: 3
benchmark_id: RHEL_9_STIG
rules:
  - stig_id: V-258106
    sv_id: SV-258106r1102061_rule
    status: auto
    comment: "This host is not in the automation group; keep the scan result."
EOF
chmod 600 /private/inventory/2026-q4/node42.example.test/RHEL_9_STIG.tailoring.yaml
```

## 5. Collect Cisco evidence

For each device, save the running configuration as `/private/evidence/<hostname>/scan.running-config`. The `hostname` command must match the directory name. Add `port-roles.csv` when topology checks need it. Mode `0600`.

`devices.json` is schema 1:

```json
{
  "schema_version": 1,
  "devices": [
    {
      "host": "ios-xe-switch-01",
      "platform": "ios-xe",
      "benchmarks": ["Cisco_IOS_XE_Switch_L2S_STIG", "Cisco_IOS_XE_Switch_NDM_STIG"]
    }
  ]
}
```

`cisco-cklb` remains the single-device command when you do not want a manifest. `cisco-batch` is the quarterly path. `cisco-xccdf` plus `xccdf-cklb` is the separate path that writes a device-named XCCDF result and then a checklist. It is not a duplicate of `cisco-batch`, and `cisco-cklb` is not a duplicate either: it scores one saved configuration without a manifest.

## 6. Dry-run the quarter

```sh
install -d -m 700 /private/inventory/2026-q4 /private/evidence /private/cisco-review/2026-q4
docket quarter --dry-run
```

`docket quarter` reads the config and stops at the first failing step. Later steps do not run. With neither `--rhel` nor `--cisco`, it does this:

1. `tailoring check` for the library and, when RHEL will run, the input root. A validation error stops the command. Nothing is written.
2. `tailoring check` again for the Cisco evidence root when Cisco will run and that path differs.
3. Skip RHEL when `input_root` is unset, is not a directory, or contains no OpenSCAP scan bundles. A directory that exists and is not mode `0700` is an error, not an absence.
4. Skip Cisco when the manifest, evidence root, and output root are all unset. Setting only some of them is an error.
5. `batch-cklb --dry-run` when RHEL is still selected.
6. `cisco-batch --dry-run` when Cisco is still selected.

`--dry-run` stops before any checklist is written. Expected shape when both platforms have evidence:

```text
QUARTER tailoring check
Checking library root: /private/stig-library
OK: RHEL_9_STIG.tailoring.yaml (root layer, ...)
VALIDATION PASSED: no issues, 0 warnings
QUARTER tailoring check (cisco evidence)
VALIDATION PASSED: no issues, 0 warnings
QUARTER batch-cklb dry-run
BENCHMARK RHEL 9: /private/stig-library/U_RHEL_9_STIG_V2R11_Manual-xccdf.xml (sha256 ...)
bundles: 12; no files written
QUARTER cisco-batch dry-run
BENCHMARK ios-xe-switch-01 Cisco_IOS_XE_Switch_L2S_STIG open=... not_a_finding=... not_applicable=... not_reviewed=...
DRY RUN no files written
QUARTER DRY RUN complete; no checklists written
```

Read every `BENCHMARK` line. The path must be this quarter's manual. The counts are candidates, not approval.

### One platform

`--cisco` converts Cisco evidence and does not read `input_root`. `--rhel` converts RHEL scans and does not read the Cisco manifest, evidence root, or output root. Passing both flags is an error. An empty RHEL tree with `--rhel` is an error. The same empty tree without `--rhel` is skipped so a Cisco-only quarter can finish.

```sh
docket quarter --cisco --dry-run
docket quarter --cisco
docket quarter --rhel --dry-run
docket quarter --rhel
```

A Cisco-only dry run prints `QUARTER skipping RHEL (--cisco)` and does not print `batch-cklb`. A RHEL-only dry run prints `QUARTER skipping Cisco (--rhel)`.

### When a step fails

Fix the file named in the error and run the same command again.

- A failure in tailoring check or in a dry run writes nothing.
- A failure while writing RHEL checklists leaves any checklists written before the failing host. The next run skips identical checklists and retries the failing host.
- A failure while writing Cisco checklists leaves the RHEL checklists from that run in place. The next run skips identical RHEL checklists and retries Cisco.

`scripts/preflight-offline.sh` checks ownership and then runs `tailoring check`. It exits non-zero when that check fails, when a tailoring file is nested below a host directory, and when `--evidence-root` names a tree whose tailoring check fails. The ownership walk requires directories and private files to be owner-only. Manual `*_Manual-xccdf.xml` files may be mode `0644`. Prefer `docket quarter --dry-run`. Use preflight when you also want the ownership walk and an optional `checkmate --list`:

```sh
scripts/preflight-offline.sh \
  --converter "$(command -v docket)" \
  --input-root /private/inventory/2026-q4 \
  --library-root /private/stig-library \
  --evidence-root /private/evidence \
  --checkmate "$(command -v checkmate)" \
  --checklist-root /private/checklists/2026-q4
```

## 7. Write the checklists

```sh
docket quarter
```

Expected ending: `QUARTER complete`. RHEL checklists appear beside each scan as `*-ASSESSMENT.cklb` plus `.provenance.json`. Cisco checklists, review HTML, and a partial `.tailoring.yaml` worksheet appear under `/private/cisco-review/2026-q4/<benchmark-id>/<host>/`. `index.html` lists them. Those CKLBs are the files security opens in STIG Viewer. Before you hand them over, confirm every in-scope host is present and that every rule has a status, a comment, finding details, and check text.

Copy a checklist into `/private/checklists/2026-q4/<host>/` only when you are about to record a site fact in checkmate. Checkmate selects the newest `.cklb` in each directory.

## 8. Hand the checklists to STIG Viewer

Security opens each host's CKLB and judges every rule on that host, including every Not a Finding. A pass on one host does not cover the next host. The comment and finding details already say what this host showed. The check text, discussion, fix, and potential impact come from the manual.

Checkmate is optional, and it is for you, not for security. Use it when a rule needs a fact the scan cannot see: banner text, an approved address, or a feature this host does not have. `--root` is the checklist tree. `checklist_root` in the config, or `DOCKET_CHECKLIST_ROOT`, is the same path when the flag is omitted. The examples pass `--root` so they work without the config file. No host starts selected. Set a status and a comment only where you have a reason. A shared STIG id is not a shared finding. Leave machine Not a Finding rows unchanged.

```sh
checkmate --root /private/checklists/2026-q4 --list
checkmate --root /private/checklists/2026-q4
```

Export the decisions every selected host already shares:

```sh
install -d -m 700 /private/tailoring-export
checkmate --root /private/checklists/2026-q4 \
  --benchmark RHEL_9_STIG \
  --export-tailoring /private/tailoring-export
```

Expected:

```text
Exported N rules to /private/tailoring-export/RHEL_9_STIG.tailoring.yaml
  Schema v3 root candidate. Run docket tailoring rehash after copying it to the library root.
```

The file is schema v3, has `benchmark_sha256: rehash-me`, and has no `rule_name`. Rows are real comments or manual status changes. A scan pass whose comment is still the converter's "XCCDF rule result" text is not exported. A comment containing `placed on the DISA rule id` or `saved running configuration on this device` is not exported. A `not_reviewed` row whose comment is empty, contains `NOT REVIEWED`, or is the converter's `DRAFT:` mapping sentence is not exported. A `not_reviewed` row with an administrator's own reason is exported as `not_reviewed`. Read the file. Delete rows that are not site policy. Then:

```sh
install -m 600 /private/tailoring-export/RHEL_9_STIG.tailoring.yaml \
  /private/stig-library/RHEL_9_STIG.tailoring.yaml
docket tailoring rehash --library-root /private/stig-library
```

Host-only exceptions stay in the host directory. Do not put them in the root file.

Cisco worksheets under the review tree are partial host files. Edit them, drop rows you do not mean to apply, and copy the result to `/private/evidence/<host>/<benchmark-id>.tailoring.yaml`.

## 9. Regenerate

After tailoring changes, or after a rescan:

```sh
docket tailoring check
docket quarter --dry-run
docket quarter
```

Unchanged inputs are skipped. A tailoring change produces a new checklist name. The previous file stays beside it. Checkmate will open the newest file in that directory, so move the old checklist out if you do not want it considered.

## 10. Archive

When the review is accepted:

```sh
install -d -m 700 /private/stig-archive/2026-q4
cp -a /private/stig-library /private/stig-archive/2026-q4/library
cp -a /private/inventory/2026-q4 /private/stig-archive/2026-q4/inventory
cp -a /private/cisco-review/2026-q4 /private/stig-archive/2026-q4/cisco-review
sha256sum /private/stig-archive/2026-q4/library/*.xml > /private/stig-archive/2026-q4/library/SHA256SUMS
```

Leave the active library in place for the next quarter's swap. Do not point `--library-root` at the archive.

## Command reference for this quarter

```sh
docket tailoring check --library-root /private/stig-library --scan-root /private/inventory/2026-q4
docket tailoring migrate --library-root /private/stig-library --dry-run
docket tailoring rehash --library-root /private/stig-library --dry-run
docket tailoring rehash --library-root /private/stig-library
docket quarter --dry-run
docket quarter
docket quarter --cisco --dry-run
docket quarter --rhel --dry-run
checkmate --root /private/checklists/2026-q4 --list
checkmate --root /private/checklists/2026-q4 --benchmark RHEL_9_STIG --export-tailoring /private/tailoring-export
```

`cisco-cklb`, `cisco-xccdf`, and `xccdf-cklb` stay available for one device or for a saved network XCCDF. The quarterly batch path is `docket quarter`.
