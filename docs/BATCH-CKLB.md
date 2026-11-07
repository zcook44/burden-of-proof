# Recursive OpenSCAP → CKLB conversion

Build the standalone Go CLI once (Go 1.22+; dependency is vendored for offline builds):

```sh
cd /home/zrc/git/burden-of-proof
install -d -m 700 dist
GOPROXY=off GOSUMDB=off go build -mod=vendor -o dist/stig-evidence ./cmd/stig-evidence
```

Run from **any working directory**. Supply the root you want to crawl with `--input-root`; there is no compiled-in lab path. Keep extracted official manual XCCDFs in a stable, owner-private `--library-root` (subdirectories are searched):

```sh
/home/zrc/git/burden-of-proof/dist/stig-evidence batch-cklb \
  --input-root /home/zrc/git/burden-of-proof/lab_results \
  --library-root /private/extracted-stig-library \
  --dry-run

/home/zrc/git/burden-of-proof/dist/stig-evidence batch-cklb \
  --input-root /home/zrc/git/burden-of-proof/lab_results \
  --library-root /private/extracted-stig-library
```

The October library ZIP contains a nested `U_RHEL_9_V2R10_STIG.zip`; extract the product ZIP too, so the library root actually contains `U_RHEL_9_STIG_V2R10_Manual-xccdf.xml` somewhere below it. Library directories must be owner-owned/private (0700), the XCCDF files owner-private (0600), and no symlinks are accepted. Every invocation selects the highest **numeric version, then numeric release** for the RHEL 9 family identified by the source XCCDF, cross-checking filename against the official benchmark ID, XML namespace, version and `release-info`. It prints the selected path and SHA-256, including during `--dry-run`; malformed candidates and equal highest releases in different paths fail closed. SSG result version `0.1.82` is *not* an official DISA release number. No download or ZIP extraction occurs during conversion.

Adding a new quarterly release to that root makes the **next invocation** use it, including for old scans. That is a deliberate current-benchmark reinterpretation, not a reconstruction of the benchmark in force when the scan ran; compare changed controls before compliance use. Different benchmark bytes produce distinct output filenames and do not overwrite earlier files. For a pinned historical conversion, use `--benchmark /private/U_RHEL_9_STIG_V2R10_Manual-xccdf.xml` **instead of** `--library-root`. Change only `--input-root` to process a different tree (including deeply nested folders). The input directory must contain host-named leaf directories; each XCCDF `TestResult/target` must equal its containing directory's basename. The scanner needs no VM access for conversion. Run `batch-cklb --help` for flags. No global `--operator-approved` is offered: approval of one run cannot be silently extended to every scan found recursively.

## Pairing and output

The crawler recognizes `<prefix>.results.xccdf.xml` or `<prefix>.results.xml` **plus** `<prefix>.report.html` within the same directory. `<prefix>.results.arf.xml` adds joined OVAL/host values when available. It ignores `.stig-viewer.xccdf.xml` (a different result representation), old CKLB files, benchmark XML and scan logs. A missing companion, duplicate XCCDF for one prefix, symlink, public directory, unreadable private input, mismatched target or conflicting evidence stops with a nonzero exit; it never falls back to another run's report. Numeric `V-…`/`SV-…` matching is the default mapping convention; it is not proof that each SSG check is semantically identical to the official DISA check. ARF+HTML yields host-observation findings; older XCCDF+HTML scans yield only values actually rendered in HTML. Missing and ambiguous controls stay Not Reviewed.

New checklists are written **beside each run** as `<prefix>-disa-<benchmark-hash>-<input-bundle-hash>-ASSESSMENT.cklb`. Earlier `-REVIEW.cklb` outputs are retained as historical artifacts, not overwritten or silently renamed. The hashes in the filename distinguish revisions and changed inputs; generated files are mode `0600` in owner-private directories. A repeated run recalculates output and skips an existing checklist **only when its complete bytes match**. A differing existing file or late name collision is an error, never an overwrite. If a later run fails, previously created outputs remain; the command reports progress so it can be safely retried.

These are *review* checklists, not signed DISA releases. Schema validation against the separately obtained official CKLB 1.0 JSON schema is still an external verification step. The Go batch command does not run the Python signature/policy release gate or prove SSG-to-DISA semantic check equivalence; the operator must review the unmatched, N/A and Not Reviewed controls. Host configuration data may be sensitive—do not commit or distribute the source scans or checklists casually.

## Exercised tree

With the local `lab_results` root and its protected V2R9/V2R10 manual XCCDF copies as a library, library-mode dry-run selected V2R10 by release metadata and found three complete bundles: one HTML-only node1 scan and two ARF+HTML node2 scans. Conversion verified and skipped all three existing V2R10 assessment files unchanged. Their original creation used the explicit V2R10 path; each was previously checked against the external CKLB 1.0 schema, all exact benchmark V/SV pairs, and the per-control source-status mapping. The two node2 scans each mapped to 372 Not a Finding, 26 Open, 8 Not Applicable and 39 Not Reviewed; the node1 scan mapped to 366, 27, 17 and 35 respectively. Actual STIG Viewer GUI import has not been exercised.
