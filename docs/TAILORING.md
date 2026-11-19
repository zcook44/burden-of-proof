# Tailoring

Tailoring is one schema, shared by `docket` and `checkmate`. Schema version 3 is the only format either tool reads. Older files are converted with `docket tailoring migrate`. They are not accepted during conversion.

A root file at the library root applies to every host of that benchmark. A host file in that host's scan or device directory overrides individual rules. Host rules win. Rules you do not list keep the scan or config result.

## Schema version 3

Root file, `<library-root>/<benchmark-id>.tailoring.yaml`:

```yaml
schema_version: 3
benchmark_id: RHEL_9_STIG
benchmark_sha256: <sha256 of the selected manual>
rules:
  - stig_id: V-258106
    sv_id: SV-258106r1102061_rule
    rule_name: sudo_remove_nopasswd   # optional, RHEL only
    status: not_a_finding
    comment: "Passwordless sudo is required for the automation account."
```

Host file, same name, beside the scan or `scan.running-config`. It has no hash. It inherits the root pin and the benchmark id.

```yaml
schema_version: 3
benchmark_id: RHEL_9_STIG
rules:
  - stig_id: V-258106
    sv_id: SV-258106r1102061_rule
    status: auto
    comment: "This host is not in the automation group; keep the scan result."
```

`benchmark_sha256` is stored only on the root file. After a new manual is placed in the library, `docket tailoring rehash --library-root <library>` rewrites those pins. `--dry-run` prints the changes and does not write. Host files are not rewritten.

Both RHEL and Cisco root files are partial. List a rule only when an administrator has a decision. Cisco no longer requires a row for every control.

### One comment rule

- A status other than `auto` needs a comment, on the root file and on a host file.
- Root `auto` may omit a comment (it changes nothing) or include one (the scan status is kept and the comment is recorded as a note).
- Host `auto` needs a comment. That row exists to undo a root decision or to say why this host differs.
- `rule_name` is optional. Checkmate does not invent one.

Statuses: `auto`, `open`, `not_a_finding`, `not_applicable`, `not_reviewed`.

## Commands

```sh
docket tailoring check --library-root /private/stig-library --scan-root /private/inventory/2026-q4
docket tailoring rehash --library-root /private/stig-library --dry-run
docket tailoring rehash --library-root /private/stig-library
docket tailoring migrate --library-root /private/stig-library --scan-root /private/inventory/2026-q4 --dry-run
```

`tailoring check` walks subdirectories of the library and selects the newest manual the same way `batch-cklb` and `cisco-batch` do: highest version, then highest release. Two files with the same version and release fail the run. A host file with no root file is a warning, not a pass of the pin: there is no pin to inherit.

`tailoring migrate` rewrites implicit, v1, and v2 files to v3. Comment-less `auto` rows are dropped, which turns an all-auto Cisco inventory into `rules: []` while keeping the root pin. Host files lose `benchmark_sha256`.

Paths may come from [the shared config](CONFIG.md).

## What the converters do

`batch-cklb`, `draft-cklb`, `cisco-cklb`, `cisco-batch`, and `cisco-xccdf` load the root file from the library root (or from the benchmark's directory when you pass `--benchmark` and no library root) and the host file from the host directory.

`cisco-batch` and `xccdf-cklb` write a partial host worksheet beside each checklist. It lists administrator overrides and not-reviewed rows. Scored passes are omitted. The worksheet has no benchmark hash. Copy the rows you mean to keep into the device directory.

`checkmate --export-tailoring DIR` writes a schema v3 root candidate per benchmark. It includes a rule only when every selected host shares the same status and comment, and only when that comment is an administrator decision. Plain scan passes and untouched "NOT REVIEWED" text are omitted. The file's pin is `rehash-me` until `docket tailoring rehash`.

## Provenance

When a file is applied, the checklist sidecar records `tailoring_root` and `tailoring_host` (path and SHA-256 of the tailoring file bytes) and `tailoring_rule_layer` (STIG id to `root` or `host`). The benchmark pin is the root file's `benchmark_sha256`, checked against the manual that was selected.

## Privacy

Tailoring files stay owner-private (`0600`). Evidence, manifests, and generated checklists stay owner-private. Official DISA manuals may be mode `0644`; the tools refuse symlinks but do not require `0600` for those XML files. The library directory itself stays `0700` because the root tailoring files sit in it.

## Migration from older files

```sh
docket tailoring migrate --library-root /private/stig-library --scan-root /private/inventory --dry-run
docket tailoring migrate --library-root /private/stig-library --scan-root /private/inventory
docket tailoring rehash --library-root /private/stig-library
docket tailoring check --library-root /private/stig-library --scan-root /private/inventory
```

Do not keep using v1 or implicit files. The converters will name `docket tailoring migrate` and stop.
