# Shared configuration

`docket` and `checkmate` read one defaults file. Every path uses the same precedence:

1. Command-line flag
2. Environment variable
3. The defaults file
4. Built-in default (usually empty, which means the command still requires the flag)

The file is `$DOCKET_CONFIG` when that variable is set. Otherwise it is `$XDG_CONFIG_HOME/docket/config.yaml`, or `~/.config/docket/config.yaml`. A missing file is ignored. A file that exists must contain only the keys below.

```yaml
# ~/.config/docket/config.yaml
library_root: /private/stig-library
input_root: /private/inventory/2026-q4
evidence_root: /private/evidence
cisco_manifest: /private/evidence/devices.json
output_root: /private/cisco-review/2026-q4
checklist_root: /private/checklists/2026-q4
```

| Key | Environment | Commands |
| --- | --- | --- |
| `library_root` | `DOCKET_LIBRARY_ROOT` | `batch-cklb`, `cisco-batch`, `cisco-cklb`, `cisco-xccdf`, `xccdf-cklb`, `tailoring`, `quarter`; bash completion of benchmark IDs |
| `input_root` | `DOCKET_INPUT_ROOT` | `batch-cklb`, `tailoring check`, `tailoring migrate`, `quarter` |
| `evidence_root` | `DOCKET_EVIDENCE_ROOT` | `cisco-batch`, `quarter` |
| `cisco_manifest` | `DOCKET_CISCO_MANIFEST` | `cisco-batch`, `quarter` |
| `output_root` | `DOCKET_OUTPUT_ROOT` | `cisco-batch`, `quarter` |
| `checklist_root` | `DOCKET_CHECKLIST_ROOT` | `checkmate --root` when the flag is omitted |

Example: with the file above, these are the same command.

```sh
docket quarter --dry-run
DOCKET_LIBRARY_ROOT=/private/stig-library docket quarter --dry-run --input-root /private/inventory/2026-q4
docket quarter --cisco --dry-run
docket quarter --rhel --dry-run
checkmate --root /private/checklists/2026-q4 --list
```

`--cisco` ignores `input_root`. `--rhel` ignores `cisco_manifest`, `evidence_root`, and `output_root`. With neither flag, a missing RHEL tree or a tree with no scan bundles is skipped, and Cisco still runs when its three paths are set. A partial Cisco trio is an error. `checkmate --root` overrides `checklist_root`.

A flag still wins over the file. `DOCKET_LIBRARY_ROOT` wins over `library_root` in the file and loses to `--library-root`.

Keep the file owner-readable. It names private trees. It does not contain scan data, device configuration, or tailoring decisions.
