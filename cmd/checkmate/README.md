# Checkmate

A terminal editor for STIG Viewer `.cklb` checklists. It reads CKLB JSON, so Cisco IOS, RHEL, and other benchmarks all get the same treatment. Apparently the paperwork is the one platform everyone agreed to standardize.

Checkmate edits checklist answers. It does **not** run scans, assess a host, approve a control, or make an incorrect answer correct by displaying it in a handsome terminal.

## Primary workflow

```mermaid
flowchart TD
    subgraph upstream["Upstream: separate tools, not Checkmate"]
        scan["External OpenSCAP scan"] --> evidence["Private same-run XCCDF + HTML + ARF"]
        evidence --> converter["burden-of-proof converter: pair scan bundle, reconcile V/SV IDs"]
        benchmark["Official DISA manual XCCDF + optional per-OS policy"] --> converter
        converter --> generated["CKLB review candidate + provenance sidecar"]
    end
    generated --> root["Owner-private CKLB --root"]
    cisco["docket: saved Cisco config and the benchmark you named; pinned checks may be decided; the rest stay for review"] --> root
    external["Other vendor CKLBs"] --> root
    root -.-> inventory["Read-only --list OR --validate --schema"]
    subgraph editor["Checkmate: deliberate in-place review"]
        root --> discover["Newest CKLB per directory, or the newest file that contains --benchmark; ties and symlinks fail"]
        discover --> group["Group by benchmark, release, group ID and rule ID"]
        group --> choose["Finder, filters, check text, found configs; select hosts explicitly"]
        choose --> preview["Choose status + comment; preview each old to new answer"]
        preview --> guard["Preflight selected files: unchanged bytes and writable staging"]
        schema["Bundled DISA CKLB schema; opt-in --schema"] -.->|Only with --schema| guard
        guard --> confirm["Bordered panel over the host list; bulk Open to Not a Finding also requires OVERRIDE"]
        confirm --> edit["Replace selected CKLBs in place; report partial failures"]
    end
    edit --> human["Human review, independent validation, approval and delivery"]
    edit -.-> stale["Existing provenance sidecar hash becomes stale"]
    edit -.-> tailor["--export-tailoring: rows every selected host already shares; rule_name stays manual"]
    tailor -.-> benchmark
```

Version 1.1.0 is the same refusal to decide for you, with a finder, a confirm panel, and an optional benchmark so a mixed root does not become a group project. `--export-tailoring` can write the rows every selected host already shares as a docket tailoring candidate. Those `rule_name` fields are placeholders, and an explicit status in that file replaces the next scan. Start with `--list` to inspect the discovered files; `--validate --schema PATH` is an optional **read-only** check, not an edit or a signoff. `--export-tailoring` is read-only too. The converter is `docket`, in the burden-of-proof checkout. Its Cisco evaluator can decide the pinned IOS, IOS-XE, and NX-OS switch checks. An all-`auto` inventory does not answer the ones it leaves Not Reviewed. In the editor, no hosts start selected. Filter and inspect each host, explicitly select only those sharing a justified answer, preview the exact old → new status and comment, then confirm. A common control ID is not a fleet-wide finding. Checkmate does not regenerate the converter's provenance, make a multi-file edit transactional, or replace a human approval process. For RHEL 7–10 practice inputs, see [offline examples](docs/OFFLINE-EXAMPLES.md). That guide is packaged; its data is not. For invented Cisco configurations and generated review candidates, see `examples/cisco-synthetic/GUIDE.md` in the source checkout (not the archive). Neither path is a substitute for independent evidence.

## Run locally

You need Go to build it. The resulting binary, sensibly, does not need Go to supervise it. The build writes to `release/`; that directory also contains tracked historical artifacts (see [disconnected installation](#disconnected-installation)):

```sh
VERSION=1.1.0  # current release; choose a newer unused version to rebuild
[ ! -e "release/checkmate_${VERSION}_linux_amd64.tar.gz" ] &&
[ ! -e "release/checkmate_${VERSION}_linux_arm64.tar.gz" ] &&
./scripts/package.sh "$VERSION"
./release/checkmate --root "$HOME/private/stig/completed_ckl" --list
./release/checkmate --root "$HOME/private/stig/completed_ckl" --benchmark Cisco_IOS_STIG --list
./release/checkmate --root "$HOME/private/stig/completed_ckl"                     # editor; no schema check
./release/checkmate --root "$HOME/private/stig/completed_ckl" --benchmark Cisco_IOS_STIG
./release/checkmate --root "$HOME/private/stig/completed_ckl" --schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"  # editor; validate selected files before writing
./release/checkmate --root "$HOME/private/stig/completed_ckl" --validate --schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"  # read-only schema check
./release/checkmate --root "$HOME/private/stig/completed_ckl" --benchmark RHEL_9_STIG --export-tailoring "$HOME/private/stig/tailoring_export"  # read-only tailoring candidates
```

`--schema` is **opt-in**. Without it, Checkmate still requires parseable CKLB JSON, STIG/rule data, IDs, and a supported status, but does **not** run full JSON Schema validation. `--validate` requires `--schema` and checks every selected newest checklist without entering the TUI; `--list` is an inventory, not schema validation, and cannot be combined with either flag. With `--schema` in editor mode, every **selected file** is schema-checked during batch preflight before any write. The tool does not silently consult a default schema. `--export-tailoring` is also read-only: it does not edit CKLBs and cannot be combined with `--list`, `--validate`, or `--schema`.

Point `--root` at a directory of completed checklists. Checkmate walks it and selects the most recently modified `.cklb` **in each directory**. A tie for newest, invalid *basic* CKLB data, or a symlink in the tree stops the run. Guessing which assessment you meant would be a bold feature for a compliance tool. Other files are ignored. If one directory has multiple benchmark checklists, only its newest CKLB is considered; put independent checklists in separate directories.

`--benchmark STIG_ID` is optional. The value is a CKLB `stig_id`, matched exactly, for example `Cisco_IOS_STIG` or `RHEL_9_STIG`. Checkmate then keeps, in each directory, the newest file that contains that benchmark, so a newer checklist for a different benchmark does not hide it. Rules from any other benchmark in the chosen file stay out of the session. Omit `--benchmark` and every newest checklist opens, same as before. A name that matches nothing stops the run and lists the benchmark IDs that were present. `--list`, `--validate`, and `--export-tailoring` honor the same choice.

Controls are grouped by benchmark ID, release text, group ID, and rule ID. Matching numbers from unrelated products or revisions do not earn a group photo together.

## Inputs, layout, and permissions

Only the completed `.cklb` tree is required by Checkmate. The optional DISA CKLB schema is bundled at `schemas/SV3_CKLB_1_0_JSON_SCHEMA.json` but must still be supplied explicitly with `--schema`. `stig_library` is **not a Checkmate input**: it belongs to the scan-to-checklist converter and may contain private DISA XCCDF benchmarks and per-OS tailoring YAML. Do not pass it as `--root`, and do not bundle its contents with Checkmate. Checkmate does not read XML, YAML, HTML, ARF, or provenance sidecars.

Example owner-private layout (mode recommendations shown; Checkmate does not change directory permissions):

```text
$HOME/private/stig/                                   0700  owner directory
├── schema/                                           0700  optional installed copy
│   └── SV3_CKLB_1_0_JSON_SCHEMA.json                 0600  bundled JSON, not the ZIP
├── stig_library/                                     0700  converter only; optional here
│   ├── U_RHEL_9_STIG_V2R10_Manual-xccdf.xml          0600  example benchmark
│   └── RHEL_9_STIG.tailoring.yaml                    0600  example policy
└── completed_ckl/                                   0700  pass THIS as --root
    ├── rhel9-node1/                                 0700
    │   ├── older.cklb                               0600  ignored if newer exists
    │   └── newer.cklb                               0600  selected by modification time
    └── switch1/                                    0700
        └── assessment.cklb                          0600
```

The account running Checkmate must be able to traverse and read every directory/file under `--root`; for edits it must also be able to create and rename a temporary file in **each selected CKLB's parent directory**. Parent-directory write permission matters even if the CKLB itself is readable. Use an owner-controlled tree and avoid concurrent writers. A private layout can be prepared without granting other users access:

```sh
umask 077
install -d -m 700 "$HOME/private/stig" "$HOME/private/stig/schema" \
  "$HOME/private/stig/completed_ckl" \
  "$HOME/private/stig/completed_ckl/rhel9-node1"
# Leave stig_library absent if you intend to create it with the extractor below.
install -m 600 /secure/incoming/assessment.cklb \
  "$HOME/private/stig/completed_ckl/rhel9-node1/assessment.cklb"
```

If your private checklist tree is `/scratch/src/admin/stig/completed_ckl`, use `--root /scratch/src/admin/stig/completed_ckl` after checking its ownership and modes; the neighboring `stig_library` is for the converter, not this editor. Work on a private **copy** when testing edits; `--list` and `--validate` are read-only.

### Optional schema requirements

- The repository and both architecture archives include the unmodified JSON extracted from DISA's [STIG Viewer 3 CKLB 1.0 schema ZIP](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/SV3_CKLB_1_0_JSON_SCHEMA.zip). SHA-256: `8b88205de07662006e1660b1decad677d344828d6687b1dd26bca15105b7bb37`. See [schema provenance and licensing caveat](schemas/PROVENANCE.md). The ZIP itself is not accepted by `--schema`.
- `--schema` must name a **readable local regular `.json` file**, not a symlink. It must declare `$schema` as `https://json-schema.org/draft/2019-09/schema`. Internal references work; external file or network references are not loaded. The file's parent directories must be traversable. Owner-controlled `0700` directories and `0600` files are recommended.
- The CLI checks the supplied file's format and draft, **not its provenance or checksum**. A different Draft 2019-09 schema may compile but is not DISA validation. Schema validity does not prove a finding correct or a checklist importable in STIG Viewer.
- The upstream ZIP has no explicit redistribution notice; the repository's license does **not** apply to this third-party schema. Verify your organization's authority before sharing the bundle beyond authorized recipients. The validator library and its Draft 2019-09 meta-schemas remain vendored for disconnected builds.

To install a private copy from the repository root (or the extracted architecture archive):

```sh
install -m 600 schemas/SV3_CKLB_1_0_JSON_SCHEMA.json \
  "$HOME/private/stig/schema/SV3_CKLB_1_0_JSON_SCHEMA.json"
sha256sum "$HOME/private/stig/schema/SV3_CKLB_1_0_JSON_SCHEMA.json"
# Compare with the published JSON hash above; Checkmate does not do that comparison for you.
```

## Prepare a private library and scan results

These helper scripts are in the **source repository**, not the binary release archive. They are for the **Go converter's** `--library-root` and `--input-root`. Checkmate itself takes a completed CKLB `--root`; it neither reads the STIG library nor imports OpenSCAP results. The scripts do not install the separately bundled CKLB JSON schema. `scripts/map-tailoring-rule-names.sh` is source-only as well. It reports SSG `rule_name` values for a file written by [`--export-tailoring`](#export-candidate-tailoring). It does not edit that file.

To extract a new library from official RHEL or Cisco STIG ZIPs, or a directory containing ZIPs **directly** (not recursively), choose a destination that does not exist. The script streams only RHEL `U_RHEL_N_STIG_VxRy_Manual-xccdf.xml` and Cisco `U_Cisco_*STIG_VxRy_Manual-xccdf.xml` / `U_Cisco_*VxRy_STIG_Manual-xccdf.xml` entries to a flat, owner-private directory. Cisco filenames include IOS/IOS-XE/IOS-XR Router and Switch, ASA, ACI, ISE, NX-OS and SNA variants; for example `U_Cisco_IOS_Router_NDM_STIG_V3R9_Manual-xccdf.xml` and `U_Cisco_ACI_RTR_Manual_V1R2_STIG_Manual-xccdf.xml`. It does not unpack PDFs, scripts, or arbitrary archive paths, does not overwrite a library, and fails on duplicate benchmark filenames. The destination's parent must already exist, be owned by you, and not be group/world writable. Source ZIPs should be obtained and verified under your organization's DISA distribution procedures; this script does not authenticate an archive or validate the XCCDF's identity.

```sh
# Example: SOURCE contains U_RHEL_9_...STIG.zip, U_Cisco_IOS_Router_...STIG.zip, etc.
./scripts/unpack-stig-library.sh \
  /scratch/src/admin/stig/stig_library_source_archives \
  "$HOME/private/stig/stig_library"
# Or use an individual ZIP as the first argument.
# Parent directory: owned by caller, not group/world writable.
# New library directory: 0700; extracted XML files: 0600.
```

Only versions actually present in the source are extracted; if a RHEL release or Cisco benchmark is missing, this script cannot supply it. The separate converter uses RHEL XCCDF results with `batch-cklb` and supports saved Cisco running-config review candidates via the explicitly selected benchmark in `cisco-cklb`; extraction alone does not classify controls. Optional `RHEL_N_STIG.tailoring.yaml` policies are **not** in the ZIP and must be placed at the library root separately, as owner-owned regular files with mode `0600`. The converter also checks benchmark identity/release metadata when it uses one.

For an existing, owner-controlled OpenSCAP results tree, inspect its proposed permission changes first. `--apply` changes **all** directories beneath the requested root to `0700` and **all** regular files to `0600`, including unrelated files in that tree. It does not change contents or ownership, and aborts before changing modes if it encounters a symlink, multiply-linked regular file, special file, foreign-owned entry, unreadable subtree, or no recognizable XCCDF result. Use the narrow results root you intend, not a parent that also contains the library. Do not run it while another process is modifying the tree; chmod across multiple files is not atomic, so a runtime failure can leave earlier entries changed.

```sh
./scripts/fix-oscap-permissions.sh /path/to/oscap-results
./scripts/fix-oscap-permissions.sh --apply /path/to/oscap-results
# Then use: docket batch-cklb --input-root /path/to/oscap-results \
#   --library-root "$HOME/private/stig/stig_library" --dry-run
```

The path must be canonical and absolute (no symlink components); the script refuses `/` and your home directory. A recognized result ends in `.results.xml`, `.results.xccdf.xml`, or `_XCCDF_Results.xml`. Permission repair does not make an incomplete or misnamed scan bundle compatible: the converter still requires its expected same-prefix companions and valid scan content. The scripts use Bash, GNU coreutils/find, and `unzip` (for extraction); test them with `bash tests/permissions-scripts.sh` on synthetic fixtures before operating on valuable evidence.

## Drive the terminal

- `j/k` or arrows: move between controls. `Tab`: focus a host. `Space`: include or exclude that host from the edit. Nothing starts selected; Checkmate has resisted the temptation to decide for your entire fleet. `Esc` clears a notice. `q` quits. `Esc` used to leave the building; that was a bold reading of cancel.
- `PgUp/PgDn`: move through affected hosts a page at a time. `Home/End`: jump to the first or last host; `Shift+Tab`: focus the previous host. The confirmation panel pages its selected-host list too. Fifty hosts no longer require a fifty-line terminal and a prayer. Each row shows the host and its status. The full path stays on the focused line, where a long directory can be admired without shoving the status off the screen.
- `f`: cycle status filters; `F`: cycle severity filters. `/` opens a finder for benchmark, group ID, rule ID, and title. `h` opens one for hosts. Both are bordered panels, because typing into the footer was how clues went to die. Type to filter, up and down to move, Enter to accept, Esc to restore the previous query. `ctrl+u` clears the line. `ctrl+w` drops the last word. Filtering does not select hosts. Selection remains a conscious act, tragically.
- `m`: replace this control's selection with hosts matching the active status filter (within the host search); with the default `all` filter, it clears selection. `A`: select every host on this rule, including hosts the search is hiding. The host line says how many are hidden. It will not pretend your search was a moral boundary. `c`: deselect every host on this rule. Quite the demanding letter.
- The browse screen shows the rule's check text under the host list, then the configuration recorded for the selected hosts. With nothing selected, that finding is the focused host. Hosts that recorded the same finding are named together. Hosts that differ get separate blocks, so a fleet of "mostly the same" does not collapse into one convenient sentence. `v` pages the full check text, every found configuration in the selection, and the comment. In the confirmation panel, `v` opens a paged old/new preview for the focused selected host; `Tab` moves to the next selected host.
- `e`: edit selected hosts. Choose `1` Open, `2` Not a Finding, `3` Not Applicable, or `4` Not Reviewed. Type a required comment (`Ctrl+J` inserts a newline), then Enter. The host list stays up. A bordered panel shows the old status, the new status, the comment, and how many hosts were in each old state. The footer under that panel is the confirm keys, not the browse keys wearing a disguise. `y` applies; `n` or Esc cancels. A successful edit clears the selection and leaves the notice until you move, so the success line is not immediately replaced by your next accident. Bulk Open → Not a Finding also requires typing `OVERRIDE`. That is not evidence; it is a speed bump with manners.

All four existing states are editable. **Select only hosts that actually share the decision**; a shared STIG ID is not a shared configuration. Full comments and finding details can be paged for review.

Status badges follow the [STIG Viewer 3.x guide](https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_STIG_Viewer_3-x_User_Guide_V1R7.pdf): Open is red, Not a Finding green, Not Applicable black on a pale badge, and Not Reviewed gray. The symbols and labels remain visible in a monochrome terminal; even the colors know better than to be your sole source of evidence.

## What an edit actually does

Checkmate replaces the status and comment for each selected control in its existing CKLB. Other JSON fields are preserved, although the JSON formatting is rewritten. It stages each file beside the original, syncs it, retains its permissions, and renames it over the original. Before the batch, it checks **all selected files** for unchanged bytes and ability to stage replacements; with `--schema`, it also validates them against the supplied schema. Each edit checks its file again before writing. A small mercy for anyone else with the same bright idea.

A multi-file edit is **not transactionally atomic**. If a later file fails, earlier files remain changed; the TUI reports how many succeeded. Do not edit the same checklists concurrently or run the tool on a tree writable by an untrusted process.

**Important:** Existing `.cklb.provenance.json` sidecars are not changed. Their recorded CKLB hashes become stale. Checkmate does not sign output or establish that a bulk decision is correct for every host. Keep a separate backup before editing irreplaceable assessments.

## Disconnected installation

From the source tree on a build host with the vendored dependencies:

```sh
VERSION=1.1.0  # current release; choose a newer unused version to rebuild
[ ! -e "release/checkmate_${VERSION}_linux_amd64.tar.gz" ] &&
[ ! -e "release/checkmate_${VERSION}_linux_arm64.tar.gz" ] &&
./scripts/package.sh "$VERSION"
(cd release && sha256sum -c SHA256SUMS)
```

The build produces `release/checkmate` for Linux amd64, Linux amd64/arm64 archives, and `release/SHA256SUMS`. Historical archives, a private-input transfer archive, and a manifest in `release/` are tracked in this checkout; the freshly built executable is ignored. Reusing an existing version overwrites tracked archives and the manifest; choose a new candidate version and review `git status` afterward. Do not assume the release directory is private or wholly ignored. Transfer the freshly built `release/checkmate_${VERSION}_linux_<arch>.tar.gz` and `release/SHA256SUMS` together. The checksum file is useless if it arrives describing a different directory.

```sh
./scripts/install-checkmate.sh "release/checkmate_${VERSION}_linux_amd64.tar.gz"
```

`install-checkmate.sh` checks that archive's line in `SHA256SUMS`, installs `checkmate` onto `~/.local/bin`, and writes bash completion for every account at `/usr/share/bash-completion/completions/checkmate`. Completion includes `--export-tailoring` with the other flags. It completes flag names, not private checklist trees. The completion write needs sudo, and the script stops if sudo cannot do it. `--from-source` builds this checkout and fails when Go is missing, older than `go.mod`, or unable to build from `vendor/` offline. No package repository is required.

Each architecture archive contains the binary, this README, [`docs/OFFLINE-EXAMPLES.md`](docs/OFFLINE-EXAMPLES.md), the installer, the completion file, the DISA JSON schema and its [provenance notice](schemas/PROVENANCE.md). It does **not** contain private checklists, scan evidence, benchmarks, or tailoring. Build and test use vendored modules with `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, and `CGO_ENABLED=0`. Packages target Linux amd64 and arm64. Building an arm64 archive is not the same thing as running it on an arm64 host, however persuasive the filename looks.

```mermaid
flowchart LR
    source["Source checkout: Go, vendor, scripts, docs, tracked fixtures"] --> pack["scripts/package.sh VERSION"]
    pack --> generic["Generic archive: binary + README + offline guide + schema + notice"]
    generic --> checksum["release/SHA256SUMS: local integrity check"]
    checksum --> offline["Authorized disconnected host: install-checkmate.sh"]
    private["Private scans, CKLB copies, benchmarks, tailoring"] -.->|Separate authorized transfer; never in generic archive| offline
```

For a **read-only deployment check**, use `scripts/preflight-offline.sh` from the separate `burden-of-proof` checkout, not from this Checkmate archive. Supply its executable converter, private scan and benchmark roots, and optionally Checkmate plus a completed-checklist root. It checks private tree ownership/modes and any root `SHA256SUMS`, runs converter `batch-cklb --dry-run`, and runs Checkmate `--list` (plus `--validate` only if you supply a schema). It creates and removes a private temporary workspace but does not scan hosts, convert evidence, or edit checklists. See the [offline examples guide](docs/OFFLINE-EXAMPLES.md#read-only-deployment-preflight) for the exact invocation. A library's example tailoring YAML can be selected by the converter; preflight warns about it, but a dry run is **not** approval to use it as site policy.

## Export candidate tailoring

`--export-tailoring DIR` reads the selected CKLBs and writes docket tailoring **candidates**. It does not edit checklists, does not read an existing tailoring file, and does not install anything into a STIG library. One file is written per benchmark: `STIG_ID.tailoring.yaml`. A rule is included only when every selected checklist that contains that benchmark and release has the same status and the same comment. Hosts that disagree are omitted. Checkmate will not invent a majority. Two releases of the same benchmark stop the run rather than collapse into one library file.

`not_reviewed` with an empty comment, or a comment containing `NOT REVIEWED`, is left out. Any other `not_reviewed` row is written as `status: auto`, which tells docket to keep the next scan's candidate. `open`, `not_a_finding`, and `not_applicable` are copied as explicit statuses. An explicit status replaces the scan result for **every** host converted with that library. The export cannot tell a reviewed decision from last quarter's scan result that merely happened to match. Read the file, and delete rows that are not policy, before it becomes site policy.

`rule_name` is `PLACEHOLDER`. CKLB JSON does not carry the SCAP Security Guide remediation name docket expects. Fill those in before a conversion. From this source checkout, not from the generic archive:

```sh
./scripts/map-tailoring-rule-names.sh \
  "$HOME/private/stig/tailoring_export/RHEL_9_STIG.tailoring.yaml" \
  "$HOME/private/stig/stig_library"
```

The script reports `rule_name` values already present beside the same `stig_id` in a reference directory. It prints them. It does not edit the export. Names it cannot find still have to come from the converter's documentation or from SSG content.

The output directory is created at mode `0700` when it is missing. A symlink is refused. Each new file is mode `0600`. An existing file stops the run before anything is replaced. `--benchmark` limits the export the same way it limits `--list`.

```sh
install -d -m 700 "$HOME/private/stig/tailoring_export"
./release/checkmate --root "$HOME/private/stig/completed_ckl" \
  --benchmark RHEL_9_STIG \
  --export-tailoring "$HOME/private/stig/tailoring_export"
```

After the placeholders are real rule names, install the file beside the manual XCCDF at the library root, mode `0600`:

```sh
install -m 600 "$HOME/private/stig/tailoring_export/RHEL_9_STIG.tailoring.yaml" \
  "$HOME/private/stig/stig_library/RHEL_9_STIG.tailoring.yaml"
```

The next `docket batch-cklb` can select it. Tailoring applies to every host of that benchmark. A host-specific answer does not belong in it. See the [offline examples guide](docs/OFFLINE-EXAMPLES.md) for the library layout. Checkmate does not run docket and does not decide that the export is approved.

For a quarterly rescan, review one quarter in the editor, export the rows every host already shares, finish `rule_name`, and point the next conversion at that library. The following quarter still needs a person for new findings and for anything the hosts did not agree on.

## Development

```sh
GOPROXY=off GOSUMDB=off go test -mod=vendor ./...
```

Keep new source scans and assessments outside this repository. This checkout already tracks selected `examples/` fixtures, `benchmarks/` content, and `release/private-offline-inputs.tar.gz` with copied RHEL scan bundles. Those are historical source-tree contents, **not** ingredients in the generic Checkmate binary archive. `.gitignore` patterns do not untrack files already in Git. Do not edit or add private assessment data to the repository; restrict access to this private remote and handle any removal from Git history as a separate, reviewed change. Stage new practice copies in an owner-private directory outside the checkout (see the [offline examples guide](docs/OFFLINE-EXAMPLES.md)). Inspect the archive manifest before distribution.

## TODO: disconnected deployment notes

Open items found during the first air-gapped end-to-end deployment. Notes will be appended as issues are discovered.

### Install / packaging

- [ ] ...

### Configuration

- [ ] ...

### Usage / workflow

- [ ] ...

### Docs fixes

- [ ] ...

### Bugs / follow-ups

- [ ] ...
