# Network STIG scan

This is the field reference for the scan row of the [install and run](README.md) command table. `cisco-xccdf` has no dry-run. The result file is the preview.

`cisco-xccdf` scores one saved running configuration into an XCCDF 1.2 TestResult named for that host. `xccdf-cklb` converts that result into a CKLB, a review page, a tailoring worksheet, and a provenance sidecar. The checklist `target_data` carries the hostname, FQDN, management IP, management MAC, role, target type, and technology area from the scan. The configuration is collected outside this archive. [Plain-language walkthrough](NETWORK-ADMIN-WALKTHROUGH.md). [Cisco config checks](CISCO-CONFIG.md).

## Names

The hostname is `--target`, the `hostname` command, the evidence directory, and the start of every scan file.

| Artifact | Path |
| --- | --- |
| Running configuration | `evidence/<host>/scan.running-config` |
| Scan result | `scans/<host>/<host>.<benchmark-id>.results.xml` |
| Checklist | `checklists/<benchmark-id>/<host>/<host>.cklb` |
| Browser page | `checklists/<benchmark-id>/<host>/<host>.review.html` |
| Admin worksheet | `checklists/<benchmark-id>/<host>/<host>.tailoring.yaml` |
| Provenance | `checklists/<benchmark-id>/<host>/<host>.cklb.provenance.json` |

`cisco-xccdf` refuses a results path whose file and parent directory are anything else. `xccdf-cklb` refuses a results file or a checklist path that fails the same test. The XCCDF `TestResult` `id` and `target` are that hostname. `target-address` is the management IP.

## Checklist target data

The converter copies these scan facts onto the CKLB. STIG Viewer shows them on the target page. The review HTML header shows the same line.

| CKLB field | Scan fact | Source |
| --- | --- | --- |
| `host_name` | `urn:xccdf:fact:asset:identifier:host_name` | `--target`. The configuration's `hostname` command must equal it. |
| `fqdn` | `urn:xccdf:fact:asset:identifier:fqdn` | `--fqdn`. It begins with `<hostname>.` |
| `ip_address` | `target-address` and the IPv4 or IPv6 asset fact | `--ip` |
| `mac_address` | `urn:xccdf:fact:asset:identifier:mac` | `--mac`. Cisco dotted form is accepted and stored as lowercase colon-separated. |
| `role` | `urn:burden:network:role` | `--role` |
| `target_type` | `urn:burden:network:target-type` | `--target-type` |
| `technology_area` | `urn:burden:network:technology-area` | `--technology`, default `Network` |
| `is_web_database` | | `false` |
| `comments` | | One line naming the FQDN, IP, and MAC, and stating that statuses come from this scan |

A missing hostname, FQDN, IP, MAC, role, or target type stops the scan before a checklist is written.

## Commands

```sh
docket cisco-xccdf \
  --config /private/evidence/ios-xe-switch-01/scan.running-config \
  --target ios-xe-switch-01 \
  --fqdn ios-xe-switch-01.example.test \
  --ip 192.0.2.4 \
  --mac 02:00:00:00:00:04 \
  --role "Access switch" \
  --target-type "Cisco IOS-XE switch" \
  --library-root /private/stig-library \
  --benchmark-id Cisco_IOS_XE_Switch_L2S_STIG \
  --port-roles /private/evidence/ios-xe-switch-01/port-roles.csv \
  --out /private/scans/ios-xe-switch-01/ios-xe-switch-01.Cisco_IOS_XE_Switch_L2S_STIG.results.xml

docket xccdf-cklb \
  --results /private/scans/ios-xe-switch-01/ios-xe-switch-01.Cisco_IOS_XE_Switch_L2S_STIG.results.xml \
  --library-root /private/stig-library \
  --out /private/checklists/Cisco_IOS_XE_Switch_L2S_STIG/ios-xe-switch-01/ios-xe-switch-01.cklb
```

`xccdf-cklb` copies each `rule-result` onto the official rule with the same SV id. `pass`, `fail`, `notapplicable`, and `notchecked` become Not a Finding, Open, Not Applicable, and Not Reviewed. It builds the checklist from the result file and writes `<host>.cklb.provenance.json`. That sidecar binds the checklist bytes to the result file, the official benchmark, the running-config SHA-256, and the tailoring SHA-256 when a policy was applied. A second pass over the configuration is a separate `cisco-cklb` or `cisco-batch` run.

`cisco-xccdf` stops when the `hostname` command is missing, conflicts with another `hostname` command, or differs from `--target`. It records `config-complete` from the snapshot: an IOS configuration is complete when it has a version line and `end`; an NX-OS configuration is complete when it has a version line and a hostname. The review page repeats that fact. Place `<benchmark-id>.tailoring.yaml` in the same directory as `scan.running-config` to apply administrator decisions on the next `cisco-xccdf` run for that device. A file beside the benchmark still applies to every device that does not have its own copy.
