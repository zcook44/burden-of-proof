# Install and run

One binary converts RHEL OpenSCAP results and Cisco running configurations into private CKLB review candidates. It does not scan a guest, log into a switch, approve a finding, or deliver evidence. Those jobs remain with people, which is inconvenient and also the point.

[Repository overview](../README.md) · [RHEL picture](RHEL-OSCAP-WORKFLOW.md) · [Cisco picture](CISCO-SCAN-PROCESS.md) · [Batch rules](BATCH-CKLB.md) · [Cisco checks](CISCO-CONFIG.md) · [Network scan fields](NETWORK-SCAN.md) · [Commands](GO-MIGRATION.md) · [Review workflow](WORKFLOW.md) · [Disconnected release](DISCONNECTED-RELEASE.md)

## 1. Install the same binary either way

On a disconnected host, verify and extract the 1.0.1 archive, then use `./bin/stig-evidence`. The [release page](DISCONNECTED-RELEASE.md) has the checksum steps. The archive does not contain official benchmarks. It is a converter, not a STIG library that fell off a truck.

From a source checkout that includes `vendor/`, build with the same flags the release script uses:

```sh
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOFLAGS=-mod=vendor
go test ./...
install -d -m 700 dist
go build -trimpath -ldflags='-s -w' -o dist/stig-evidence ./cmd/stig-evidence
```

A shorter build command will usually produce a binary. It will not be the binary this release claims to be.

## 2. Stage one private library

Use one owner-owned mode `0700` directory, for example `/private/stig-library`. Copy authorized manual XCCDF files into it at mode `0600`. RHEL and Cisco benchmarks may share that directory. The CLI selects a RHEL file from the scan's OS, and a Cisco file only when you pass its exact `--benchmark-id` or `--benchmark` path. It will not guess. It has met people.

A Git checkout of `stig-library-cisco/` is mode `0644` and is not an operational library. Stage a private copy. Do not point the CLI at the checkout and hope.

Tailoring files are optional and dangerous when copied casually:

| Family | File | Who it applies to |
| --- | --- | --- |
| RHEL | `RHEL_<major>_STIG.tailoring.yaml` at the library root | Every host of that OS |
| Cisco | `<benchmark-id>.tailoring.yaml` beside that benchmark | Every device that does not have its own copy |
| Cisco, one device | `<benchmark-id>.tailoring.yaml` beside that device's `scan.running-config` | That device only |

`auto` keeps the tool's status. Any other status needs a nonempty comment. The packaged RHEL examples are not site policy. The RHEL 9 example contains a lab-specific `not_a_finding`. Installing it unchanged is how a joke becomes a finding.

## 3. Name the asset the same way on disk

| Family | Directory name | Must also match |
| --- | --- | --- |
| RHEL | The XCCDF `TestResult/target`, usually the FQDN | The scan file lives in that directory |
| Cisco | The short `hostname` command | `--target` is that same string |

The scan commands add the rest of the checklist target page, and only there: `--fqdn` must begin with `<hostname>.`, plus `--ip`, `--mac`, `--role`, and `--target-type`. `cisco-cklb` records the target you pass and checks the directory name. `cisco-batch` and `cisco-xccdf` also refuse a configuration whose `hostname` command disagrees. Nicknames are not a feature.

Inputs are owner-private: directories `0700`, files `0600`, no symlinks.

## 4. Pick one command

| You have | Command | Preview | Checklist lands |
| --- | --- | --- | --- |
| A tree of RHEL OpenSCAP results | `batch-cklb` | `preflight-offline.sh`, then `--dry-run` | Beside each scan: `<prefix>-disa-…-ASSESSMENT.cklb` and `.cklb.provenance.json` |
| One Cisco configuration and one benchmark | `cisco-cklb` | `--dry-run` | Beside the configuration: `<prefix>-cisco-…-ASSESSMENT.cklb` and provenance |
| Many Cisco devices | `cisco-batch` | `--dry-run` | `--output-root/<benchmark-id>/<host>/`, plus `index.html` |
| A Cisco result that must carry IP, FQDN, and MAC | `cisco-xccdf`, then `xccdf-cklb` | No dry-run. The first command writes the result. | `checklists/<benchmark-id>/<host>/<host>.cklb`, provenance, review page, and tailoring worksheet |

`cisco-xccdf` has no dry-run because a result file is the point of the command. Read the path twice.

```sh
# RHEL. Omit --dry-run only after the printed benchmark is the one you meant.
./dist/stig-evidence batch-cklb \
  --input-root /private/inventory \
  --library-root /private/stig-library \
  --dry-run

# One switch. --target is the hostname command, not a friendly alias.
./dist/stig-evidence cisco-cklb \
  --config /private/configs/ios-xe-switch-01/scan.running-config \
  --target ios-xe-switch-01 \
  --library-root /private/stig-library \
  --benchmark-id Cisco_IOS_XE_Switch_L2S_STIG \
  --dry-run

# Device-named result, then the checklist.
./dist/stig-evidence cisco-xccdf \
  --config /private/configs/ios-xe-switch-01/scan.running-config \
  --target ios-xe-switch-01 \
  --fqdn ios-xe-switch-01.example.test \
  --ip 192.0.2.4 \
  --mac 02:00:00:00:00:04 \
  --role "Access switch" \
  --target-type "Cisco IOS-XE switch" \
  --library-root /private/stig-library \
  --benchmark-id Cisco_IOS_XE_Switch_L2S_STIG \
  --out /private/scans/ios-xe-switch-01/ios-xe-switch-01.Cisco_IOS_XE_Switch_L2S_STIG.results.xml

./dist/stig-evidence xccdf-cklb \
  --results /private/scans/ios-xe-switch-01/ios-xe-switch-01.Cisco_IOS_XE_Switch_L2S_STIG.results.xml \
  --library-root /private/stig-library \
  --out /private/checklists/Cisco_IOS_XE_Switch_L2S_STIG/ios-xe-switch-01/ios-xe-switch-01.cklb
```

On a first RHEL deployment, run `scripts/preflight-offline.sh` before the write. The example without Checkmate is the one that matches this archive. Add Checkmate only when that separate tool is actually installed. Details and the with-Checkmate form are in the [release notes](DISCONNECTED-RELEASE.md).

A repeated run with the same bytes skips. A different result is never silently overwritten. If that feels stubborn, it is the feature.

## 5. Read the candidate, then stop

Review Open, then Not Reviewed, then Not Applicable, then a sample of Not a Finding. Import a representative checklist into STIG Viewer before anyone calls it adopted. Checkmate, when supplied separately, can list or schema-check existing CKLBs. Editing one there makes the provenance hash stale, which is the tool's way of refusing to cosign your edits.

RHEL details: [batch converter](BATCH-CKLB.md) and the [picture](RHEL-OSCAP-WORKFLOW.md). Cisco check behavior: [Cisco config](CISCO-CONFIG.md). Scan fields: [network scan](NETWORK-SCAN.md). The demo script for people who do not want a flag reference: [admin walkthrough](NETWORK-ADMIN-WALKTHROUGH.md).
