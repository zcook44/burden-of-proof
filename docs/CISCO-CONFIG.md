# Cisco running-config review candidates

The shared install, library, and command choice are in [install and run](README.md). This page is what the pinned checks will and will not decide. The tool is not shy about the second list.

The repository tracks `stig-library-cisco/`: 25 official manual XCCDF XMLs and 25 partial schema v3 root tailoring files. Each YAML pins its manual and has `rules: []`. Those pins are not an assessment. The XMLs are **not** included in the generic offline archive; the partial YAML examples are. A Git checkout does not preserve private modes: copy authorized manuals into an owner-owned `0700` library. Manuals may be `0644`. Tailoring stays `0600`. Do not commit operational configs or decisions.

`docket cisco-cklb` scores one saved running configuration against one official Cisco manual benchmark. `docket cisco-batch` does that for every device and benchmark in a manifest and writes a separate review folder for each, plus an HTML index a reviewer can open. Pinned checks cover IOS and IOS-XE switch NDM controls that are decided by global commands, and IOS, IOS-XE, and NX-OS switch L2S controls that can be decided from the configuration together with a port-role table. Every other control stays `not_reviewed`. The tool does not connect to a device, infer platform or role from the configuration, or copy raw configuration lines into the checklist.

```mermaid
flowchart TD
  A[Authorized saved running-config in private target directory] --> C[Operator confirms platform and role]
  B[Official manual XCCDF and optional complete YAML inventory in private library] --> C
  C --> D[Select exact benchmark ID or pinned XML; dry-run validates inputs]
  D --> E[Pinned checks: IOS and NX-OS switch L2S and switch NDM]
  E --> F[Other or ambiguous checks: not_reviewed]
  E --> G[Bounded config-only verdict when decisive]
  F --> H[Partial root policy; explicit admin override needs a comment]
  G --> H
  H --> I[No-overwrite private CKLB and byte-bound provenance]
  I --> J[Independent schema validation and human review with additional state evidence]
  J --> K[Separate authorization and release process; not performed here]
```

## Inputs and selection

Use an owner-owned, mode-`0700` directory named exactly for the device. Place an owner-owned, mode-`0600` UTF-8 snapshot ending in `.running-config` inside it. The CLI requires an explicit `--target` matching that directory. Supply either one owner-private Cisco manual XCCDF XML with `--benchmark` or an owner-private library and **exact** `--benchmark-id`, for example `Cisco_IOS_Router_NDM_STIG`. A router may require separate NDM and RTR benchmarks; use a separate invocation for each. The library selector chooses the newest V/R pair for that exact ID, refuses equal-version duplicates, and checks XCCDF identity and release metadata against the file name. It does **not** guess IOS vs IOS-XE, router vs switch, or NDM vs RTR from config text. Never use a benchmark for a different platform or role merely because it was in the same ZIP.

```sh
docket cisco-cklb \
  --config /private/configs/router1.example.test/scan.running-config \
  --target router1.example.test \
  --library-root /private/stig-library \
  --benchmark-id Cisco_IOS_Router_NDM_STIG \
  --dry-run
# Remove --dry-run only after independently confirming device identity and benchmark applicability.

docket cisco-batch \
  --manifest /private/configs/review-manifest.json \
  --evidence-root /private/configs \
  --library-root /private/stig-library \
  --output-root /private/cisco-review \
  --dry-run
```

`cisco-batch` reads `schema_version: 1` and a `devices` list. Each device has `host`, `platform` (`ios`, `ios-xe`, or `nxos`), and the exact benchmark IDs to run. The host directory must be named for that host and contain `scan.running-config`. The `hostname` command must match the directory name. A switch that uses the per-port checks also has `port-roles.csv` with the header `interface,role,user_facing,fiber`. Roles are `user`, `uplink`, `unused`, `access-switch`, and `routed`. The batch writes `--output-root/<benchmark-id>/<host>/` so NDM, L2S, and RTR stay visible together, plus `index.html`.

## Layered Cisco tailoring

For each selected Cisco benchmark, the CLI uses layered tailoring. The root file is `<exact-benchmark-id>.tailoring.yaml` at `--library-root` (not in a subdirectory of the manual). It is partial: only the rules you are deciding, plus `benchmark_sha256` of the newest manual for that id. **Host overrides** load from `<exact-benchmark-id>.tailoring.yaml` in the device directory beside `scan.running-config`. Host files omit `benchmark_sha256`. Rules merge per rule; the host row wins.

Schema version 3 is the only format the Cisco commands read. A root file has `benchmark_id`, `benchmark_sha256`, and a partial `rules` list. A host file has the same shape without `benchmark_sha256`. `auto` leaves the evaluator's status unchanged. A non-`auto` status needs a comment. Host `auto` needs a comment. See [TAILORING.md](TAILORING.md).

An administrator can deliberately change one `status` to `open`, `not_a_finding`, `not_applicable`, or `not_reviewed`, **and must add a nonempty `comment`** explaining the decision. Root files beside the benchmark apply to every device. **Host overrides** are `<benchmark-id>.tailoring.yaml` in that device's directory, next to `scan.running-config`, not a second cloned library. Host files stay partial and use schema version 3. Never place sensitive material in comments copied into the CKLB. The checklist preserves the prior automated candidate in `finding_details`, marks the admin decision in `comments`, and records exact overridden V/SV IDs, before/after status, and both policy paths/hashes in provenance. Exact policy bytes change the CKLB ID and output filename, preserving older checklists. Without a policy, output identity stays on evaluator `cisco-config-review-v9`. An empty `rules` list does not make unsupported rules compliant.

`cisco-batch` and `xccdf-cklb` write a partial schema v3 host worksheet beside each review page. Scored passes are omitted. Not Reviewed rows and administrator overrides remain. Copy the rows you mean to keep to the device directory as `<benchmark-id>.tailoring.yaml`. Do not add `benchmark_sha256` there. The next run merges the library-root file with that host file.

`python3 scripts/generate-cisco-tailoring.py --library-root PRIVATE_CISCO_LIBRARY --dry-run` previews one partial schema v3 root file per manual (`rules: []` plus the benchmark pin). Omit `--dry-run` to create those files. It refuses to overwrite an existing policy. Manuals may be mode `0644`. After a new manual, run `docket tailoring rehash` instead of regenerating over an edited file. Keep operational edits and device configs out of Git.

## CKLB and evidence boundary

The output uses the same CKLB `stigs`/`rules` field structure as RHEL conversion. Its target is the explicit device name and its rule IDs come from the selected official benchmark. A pinned check fires only when the benchmark ID, V-ID, SV-ID, requirement version, title fragment, and official check phrases still match. Loop Guard is Not a Finding only when the global command is present and no interface has `spanning-tree guard none`. Rapid STP is Not a Finding only when the port-role table records an uplink or access-switch port and the mode is Rapid STP or MSTP. Banner text and macro bodies are not commands. A complete IOS snapshot ends with `end`; a missing command on a complete snapshot can be Open. An incomplete snapshot does not turn a missing command into a finding.

Finding details bind the raw running-config and benchmark SHA-256 values and record an allowlisted observation. Raw configuration lines are never copied. The provenance sidecar binds the CKLB bytes, config and benchmark paths/hashes, optional port-role hash, evaluator version `cisco-config-review-v9`, and per-status counts. Output filenames incorporate a versioned digest. An unchanged run verifies and skips identical outputs. Existing differing output is never silently overwritten.

A CKLB candidate is not an approved checklist. Security opens each device's CKLB in STIG Viewer and judges every rule, including every Not a Finding. `cisco-batch` already places each benchmark in its own directory, which is the layout Checkmate can inventory without hiding a second benchmark. An edit in an external editor leaves the converter's provenance hash stale. No Cisco production configuration was used to claim control status in the synthetic tests.

## Device-named scan results

`cisco-xccdf` writes the same pinned verdicts into an XCCDF 1.2 TestResult, and `xccdf-cklb` copies those verdicts onto a checklist. The results file is `<host>/<host>.<benchmark-id>.results.xml`. The checklist is `<benchmark-id>/<host>/<host>.cklb`, with `<host>.cklb.provenance.json` beside it. Both commands refuse any other name. The configuration's `hostname` command must equal `--target`; a conflicting hostname stops the scan. The result's `target` is the hostname, `target-address` is the management IP, and a fact records whether the snapshot is complete. Asset facts carry the FQDN, MAC, role, target type, and technology area, and the checklist `target_data` is filled from those facts. A `<benchmark-id>.tailoring.yaml` beside `scan.running-config` is applied before the result is written. The review page names that device's tailoring worksheet and says when the snapshot is incomplete. [Paths and fields](NETWORK-SCAN.md). [Demo script](NETWORK-ADMIN-WALKTHROUGH.md).
