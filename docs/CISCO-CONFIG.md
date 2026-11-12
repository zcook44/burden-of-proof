# Cisco running-config review candidates

`stig-evidence cisco-cklb` accepts a saved **Cisco running configuration** and one exact official DISA Cisco manual XCCDF benchmark. It creates a private, versioned CKLB review candidate and `.cklb.provenance.json` beside the input. It does **not** connect to a device, run show commands, infer which device role applies, or execute the benchmark's prose checks. A running configuration cannot establish operational state, authentication-server behavior, remote peer state, or applicability of every control. Therefore **every status starts `not_reviewed`** (STIG Viewer “Not Reviewed” / operator “Needs Review”); no absence or presence of a command is automatically a compliant finding. This is intentionally narrower than the RHEL converter's explicit SSG rule-result mapping.

## Inputs and selection

Use an owner-owned, mode-`0700` directory named exactly for the device. Place an owner-owned, mode-`0600` UTF-8 snapshot ending in `.running-config` inside it. The CLI requires an explicit `--target` matching that directory. Supply either one owner-private Cisco manual XCCDF XML with `--benchmark` or an owner-private library and **exact** `--benchmark-id`, for example `Cisco_IOS_Router_NDM_STIG`. A router may require separate NDM and RTR benchmarks; use a separate invocation for each. The library selector chooses the newest V/R pair for that exact ID, refuses equal-version duplicates, and checks XCCDF identity and release metadata against the file name. It does **not** guess IOS vs IOS-XE, router vs switch, or NDM vs RTR from config text. Never use a benchmark for a different platform or role merely because it was in the same ZIP.

```sh
stig-evidence cisco-cklb \
  --config /private/configs/router1.example.test/scan.running-config \
  --target router1.example.test \
  --library-root /private/stig-library \
  --benchmark-id Cisco_IOS_Router_NDM_STIG \
  --dry-run
# Remove --dry-run only after independently confirming device identity and benchmark applicability.
```

For an exact pinned file, replace the two library flags with `--benchmark /private/stig-library/U_Cisco_IOS_Router_NDM_STIG_V3R9_Manual-xccdf.xml`. The extractor in the separate Checkmate source repository, `scripts/unpack-stig-library.sh`, can unpack allowlisted RHEL and Cisco manual XCCDF files from ZIPs into a new private library. Official benchmark ZIPs and raw configs are obtained and transferred separately; **do not commit or bundle them with generic binaries**. The extractor does not authenticate DISA provenance. The converter archive does not currently include that helper.

## CKLB and evidence boundary

The output uses the same CKLB `stigs`/`rules` field structure as RHEL conversion, including per-rule `comments` and `finding_details`; its target is the explicit device name and its rule IDs come from the selected official benchmark. Finding details bind the raw running-config and benchmark SHA-256 values but **do not embed raw configuration lines** (they may contain secrets). The adjacent sidecar binds the exact CKLB bytes, config and benchmark paths/hashes, and marks the method `config-only`. Output filenames incorporate a Cisco-specific versioned input digest; an unchanged run verifies and skips identical outputs, while changed inputs create a distinct candidate. Existing differing output is never silently overwritten. A sidecar failure may leave a CKLB for safe inspection/retry.

A CKLB candidate is not a scanner result, STIG Viewer import test, approved checklist, or signed evidence release. A reviewer must inspect the *official check text* against the saved configuration and independently collected show/state evidence, then deliberately answer controls in a separate review process such as Checkmate. **When multiple Cisco benchmarks produce CKLBs in one device directory, Checkmate's newest-per-directory discovery sees only one:** stage private copies in separate benchmark-specific directories before using that editor. An edit there leaves the converter's provenance hash stale. Store snapshots and CKLBs in approved private storage, and handle device credentials/secrets according to policy. No Cisco production configuration was used to claim control status in the synthetic tests.
