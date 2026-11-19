# Offline example inputs (separate private copies)

Checkmate edits CKLB files; it does not convert scans. The source checkout contains tracked `cmd/checkmate/examples/` fixtures and `cmd/checkmate/benchmarks/` files, including selected RHEL 7–10 material. Do not edit the tracked copies to try the TUI. A new copy in an owner-private directory outside the checkout is the rehearsal. The runtime archive installs `checkmate` beside `docket` and does not contain those examples.

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

From the repository root, with Go 1.22 or newer:

```sh
./scripts/package-disconnected.sh 2.1.0 ./dist/releases
./scripts/install-docket.sh --prefix "$HOME/.local" ./dist/releases/ceasefire-2.1.0-linux-amd64.tar.gz
checkmate --root "$HOME/private/checkmate-practice/examples" --list
checkmate --root "$HOME/private/checkmate-practice/examples" --benchmark RHEL_9_STIG --list
checkmate --root "$HOME/private/checkmate-practice/examples" --validate \
  --schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"
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

The export is schema v3 and does not invent `rule_name`. Explicit statuses override the next scan for every host of that benchmark. Run `docket tailoring rehash` after you install the file at the library root. Do not treat the draft as approved site policy.

To test conversion read-only:

```sh
docket batch-cklb --dry-run \
  --input-root "$HOME/private/checkmate-practice/examples" \
  --library-root "$HOME/private/checkmate-practice/benchmarks"
```

The staged bundles include HTML and ARF. Permission and naming validity alone do not establish assessment correctness.

## Read-only deployment preflight

`scripts/preflight-offline.sh` is in this repository. With the installed binaries and owner-private, canonical absolute paths:

```sh
scripts/preflight-offline.sh \
  --converter "$(command -v docket)" \
  --input-root "$HOME/private/checkmate-practice/examples" \
  --library-root "$HOME/private/checkmate-practice/benchmarks" \
  --checkmate "$(command -v checkmate)" \
  --checklist-root "$HOME/private/checkmate-practice/examples" \
  --schema "$PWD/schemas/SV3_CKLB_1_0_JSON_SCHEMA.json"
```

The script runs `tailoring check`, `batch-cklb --dry-run`, and `checkmate --list`. `--schema` adds `--validate`. It does not run a scan or edit a checklist. A tailoring check failure exits non-zero. An already edited staged CKLB will fail a manifest check. Do not treat example tailoring selected by the converter as approved site policy.

## Transfer private inputs separately

The runtime archive omits example scans, CKLBs, benchmarks, and tailoring. If authorized to move staged inputs, make a distinct owner-private archive outside the checkout and verify it after transfer.

```sh
umask 077
cd "$HOME/private/checkmate-practice"
tar -czf private-offline-inputs.tar.gz examples benchmarks
sha256sum private-offline-inputs.tar.gz > private-offline-inputs.sha256
sha256sum -c private-offline-inputs.sha256
```

Transfer only to authorized recipients. Extract under an owner-private directory (`0700`), then check `(cd examples && sha256sum -c SHA256SUMS)` and `(cd benchmarks && sha256sum -c SHA256SUMS)`. Hashes check byte integrity, not the authenticity of source evidence.
