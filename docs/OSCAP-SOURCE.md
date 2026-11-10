# Lab OpenSCAP scan source and converter handoff

The **live scan playbook** is `/scratch/ansible/playbooks/oscap_scan.yml` in the operator's Ansible lab. This evidence repository does not run it. [Verbatim snapshot](snapshots/oscap_scan.yml) is included for offline review; its SHA-256 at capture was `4f51a068055de8e2c825a0bb26814e7393a45d76e479bef9d3ae3b8697fc4364`. Check `sha256sum /scratch/ansible/playbooks/oscap_scan.yml docs/snapshots/oscap_scan.yml` and compare the files before treating the snapshot as the current live playbook. The lab copy remains authoritative; this snapshot is **not** a second deployment playbook.

## Exact scan command in the playbook

The managed-host `ansible.builtin.shell` task contains this command (YAML `>-` folds its lines into a shell command). Jinja `quote` escapes each resolved path; `remote_scan_dir.path` is a newly created **guest-side** temporary directory. The profile and flags are literal in the playbook—not defaults invented by the converter:

```yaml
oscap xccdf eval
--profile xccdf_org.ssgproject.content_profile_stig_gui
--stig-viewer {{ (remote_scan_dir.path ~ '/' ~ hname ~ '_' ~ date ~ '_XCCDF_Results.xml') | quote }}
--results {{ (remote_scan_dir.path ~ '/' ~ scan_prefix ~ '.results.xml') | quote }}
--results-arf {{ (remote_scan_dir.path ~ '/' ~ scan_prefix ~ '.results.arf.xml') | quote }}
--report {{ (remote_scan_dir.path ~ '/' ~ scan_prefix ~ '.report.html') | quote }}
{{ ('/usr/share/xml/scap/ssg/content/ssg-rhel' ~ major_vers ~ '-ds.xml') | quote }}
> {{ (remote_scan_dir.path ~ '/' ~ hname ~ '_' ~ date ~ '_Scan.log') | quote }} 2>&1
```

`scan_prefix` is `{{ hname }}_{{ date }}`; `hname` is the uppercase inventory hostname, `date` is the **guest fact** date, and `major_vers` is the guest's RHEL major version. Thus for an inventory host `rhel9-node1` on guest date `2026-11-09`, the datastream is `/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml`, and the ordinary XCCDF is `<guest-temp>/RHEL9-NODE1_2026-11-09.results.xml`. Actual temporary directory names vary per run. The playbook has **no `--remediate`** flag; its `failed_when` accepts OpenSCAP exit codes **0 and 2**, rejecting other codes. It does not choose a fallback profile: confirm `stig_gui` exists in the installed datastream before attempting a new OS image. The four saved NODE1 XCCDF TestResult IDs in the private Q4_2026 tree identify `stig_gui`; that observation is not a guarantee about future SSG packages.

Before the scan, the playbook uses `become: true` and `yum state: latest` to install/update `openscap` and `scap-security-guide` on the **managed host**. This changes guest packages; it is not a read-only audit operation. The scan condition checks a kernel major of at least 3. The shell's redirected stdout/stderr is captured to the guest-side `_Scan.log` because some probe output is not UTF-8. Treat a code-2 scan as containing findings, not as evidence of a complete or approved assessment.

## What reaches the controller

After scanning, the playbook delegates directory creation and file-mode restriction to localhost (`become: false`). It makes an owner-private `0700` tree under `/scratch/src/admin/stig/completed_ckl/{{ qtr }}{{ year }}/rhel{{ major_vers }}/{{ hname }}/scan_{{ date }}_*/{{ target_fqdn }}/`. `qtr` includes its trailing underscore (for example `Q4_2026`), and `target_fqdn` comes from gathered guest facts. The host leaf must match the XCCDF `TestResult/target` for conversion. The controller's `ansible.builtin.fetch` uses `flat: true`, `fail_on_missing: true`, and `validate_checksum: true`; it copies these **five** same-prefix outputs from the guest temporary directory, then sets each to `0600`:

| Guest `oscap` output | Converter input? | Purpose |
| --- | --- | --- |
| `<prefix>.results.xml` | Required | Ordinary XCCDF result and status/reference mapping |
| `<prefix>.results.arf.xml` | Optional, with matching HTML | ARF/OVAL host observations |
| `<prefix>.report.html` | Optional | Executed checks and observations |
| `<prefix>_XCCDF_Results.xml` | No | `--stig-viewer` export, retained separately |
| `<prefix>_Scan.log` | No | Raw scanner output and diagnostics |

The playbook removes its guest temporary staging **only after** successful fetch and permission restriction, then reports the controller evidence path. A failure earlier in the block can leave guest temporary files for investigation. The Go converter never fetches results or runs OpenSCAP: it reads the first three matching files from owner-private host directories via `stig-evidence batch-cklb --input-root ... --library-root ...`. See [pairing and output](BATCH-CKLB.md#pairing-and-output). The official DISA manual XCCDF library and per-OS checklist tailoring are separate converter inputs; the SSG datastream in the `oscap` command is **not** that manual benchmark.

## Invocation boundary

From `/scratch/ansible`, the operator's `scripts/run-lab-oscap.sh` selects `inventory.yml` for RHEL 8–10 and `inventory-rhel7.yml` plus `./ansible-ee` for RHEL 7. It invokes the playbook with `--limit "$host"` after booting and waiting for each inventory-listed guest, and requests graceful shutdown afterward. `scripts/run-lab-oscap.sh --dry-run` previews the guest list without scanning. An actual run may update guests, create private evidence, and shut down **every** listed domain on exit, including one that was running before invocation; confirm lab state before using it. This wrapper and the live playbook are outside burden-of-proof and outside its disconnected release. Do not copy real scan logs, result XML, CKLBs, or local benchmark library into Git.
