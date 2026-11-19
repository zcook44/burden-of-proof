# Offline example inputs (separate private copies)

Checkmate edits CKLB files; it does not convert scans. The source checkout currently contains tracked `examples/` fixtures and `benchmarks/` files, including selected RHEL 7–10 material. It also tracks `release/private-offline-inputs.tar.gz`, a previously committed copy of RHEL scan bundles; this is **source history**, not a generic binary-package ingredient. Git ignore patterns do not protect files already tracked. Do not edit them to try the TUI. A new copy in an owner-private directory outside the checkout is the safer rehearsal. This guide and the schema travel in the generic binary archive; the example data does not. Apparently the binary is less interested in your host evidence than Git once was.

## Stage from authorized source trees

From the Checkmate source checkout, use an existing, canonical, owner-owned output directory that is not group/world writable. Its `examples/` and `benchmarks/` children must be absent. The default `--output` is the checkout and **will fail here** because those destinations already exist. Python 3's standard library suffices. The input layout must have exactly one `RHELN-NODE1/scan_*/<host>` under each `rhelN` directory; for multiple runs, first prepare a private source selection with one desired run per OS. The script refuses symlinks, non-private source files and existing destinations. It copies one same-run XCCDF result, HTML report, ARF and existing CKLB per OS, without provenance sidecars. It also copies the highest V/R manual XCCDF XML and the corresponding converter tailoring YAML per OS. It writes a SHA256SUMS file in each destination tree, not in the original source trees.

```sh
umask 077
install -d -m 700 "$HOME/private/checkmate-practice"
python3 scripts/stage-offline-examples.py \
  --scan-root /scratch/src/admin/stig/completed_ckl/Q4_2026 \
  --library-root /scratch/src/admin/stig/stig_library \
  --output "$HOME/private/checkmate-practice"
(cd "$HOME/private/checkmate-practice/examples" && sha256sum -c SHA256SUMS)
(cd "$HOME/private/checkmate-practice/benchmarks" && sha256sum -c SHA256SUMS)
```

The script selects the benchmark files available in the source library; it does not authenticate DISA bytes or validate the source CKLB against the separate schema. The examples are private copied assessment material, not sanitized demonstration data. Tailoring YAML is converter policy input. Checkmate does not read it. `--export-tailoring` can write a candidate from reviewed CKLBs; an example policy still requires separate site approval before use.

## Exercise after an offline build

```sh
VERSION=1.1.0  # current release; choose a newer unused version to rebuild
[ ! -e "release/checkmate_${VERSION}_linux_amd64.tar.gz" ] &&
[ ! -e "release/checkmate_${VERSION}_linux_arm64.tar.gz" ] &&
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor ./scripts/package.sh "$VERSION"
./scripts/install-checkmate.sh "release/checkmate_${VERSION}_linux_amd64.tar.gz"
checkmate --root "$HOME/private/checkmate-practice/examples" --list
checkmate --root "$HOME/private/checkmate-practice/examples" --benchmark RHEL_9_STIG --list
checkmate --root "$HOME/private/checkmate-practice/examples" --validate \
  --schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"
# Interactive editor; changes only your practice copies:
checkmate --root "$HOME/private/checkmate-practice/examples"
```

`--list` and `--validate --schema` are read-only; the editor replaces selected CKLBs in place. `--benchmark RHEL_9_STIG` opens that benchmark and leaves the others for another sitting. Omit it and every newest checklist opens, which is either the plan or a very long afternoon. `/` and `h` open finders. They do not select hosts. After an edit, the copied `examples/SHA256SUMS` fails until you explicitly account for that change or re-stage from the source. Existing converter provenance sidecars are not copied or refreshed. A successful schema check is not a finding review, a STIG Viewer import, or approval.

To draft tailoring from the practice copies, write somewhere new. Do not point the export at `benchmarks/`: those YAML files are hashed, and replacing them with placeholders is not a policy update. One host per OS means almost every non-default row looks unanimous. That is a sample, not a fleet.

```sh
install -d -m 700 "$HOME/private/checkmate-practice/tailoring-export"
checkmate --root "$HOME/private/checkmate-practice/examples" \
  --benchmark RHEL_9_STIG \
  --export-tailoring "$HOME/private/checkmate-practice/tailoring-export"
```

`rule_name` in that file is `PLACEHOLDER`. Explicit statuses would override the next scan for every host of that benchmark. From the source checkout, `scripts/map-tailoring-rule-names.sh` can report names already used beside the same `stig_id` in `benchmarks/` or another library. It does not edit the export. The script is not in the generic archive. Do not treat the draft as approved site policy.

To test conversion read-only, run the **separate** converter's `batch-cklb --dry-run` using absolute `--input-root "$HOME/private/checkmate-practice/examples"` and `--library-root "$HOME/private/checkmate-practice/benchmarks"`. The staged bundles include HTML+ARF; whether a particular converter build accepts them must be checked with that build. Permission and naming validity alone do not establish assessment correctness.

## Read-only deployment preflight

The optional `scripts/preflight-offline.sh` belongs to the **separate** converter checkout, not Checkmate. With a separately built executable converter and owner-private, canonical absolute paths to the staged inputs:

```sh
/path/to/burden-of-proof/scripts/preflight-offline.sh \
  --converter /private/bin/docket \
  --input-root "$HOME/private/checkmate-practice/examples" \
  --library-root "$HOME/private/checkmate-practice/benchmarks" \
  --checkmate "$PWD/release/checkmate" \
  --checklist-root "$HOME/private/checkmate-practice/examples"
# Optional: add --schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"
```

Verify the separate script's interface in that checkout before running it. Its expected contract is a dry-run converter check, Checkmate `--list`, and optional schema validation; it does not run a scan or perform a checklist edit. An already edited staged CKLB will fail a manifest check. Do not treat example tailoring selected by the converter as approved site policy.

## Transfer private inputs separately

The generic Checkmate archives deliberately omit example scans, CKLBs, benchmarks and tailoring. If authorized to move staged inputs, make a distinct owner-private archive outside the checkout and verify it after transfer. Do not copy it over the already tracked `release/private-offline-inputs.tar.gz`: that historical archive is not a suitable destination for new assessments, and an archive under `release/` is not magically ignored.

```sh
umask 077
cd "$HOME/private/checkmate-practice"
tar -czf private-offline-inputs.tar.gz examples benchmarks
sha256sum private-offline-inputs.tar.gz > private-offline-inputs.sha256
sha256sum -c private-offline-inputs.sha256
```

Transfer only to authorized recipients. Extract under an owner-private directory (`0700`), then check `(cd examples && sha256sum -c SHA256SUMS)` and `(cd benchmarks && sha256sum -c SHA256SUMS)`. Hashes check byte integrity, not the authenticity of source evidence.
