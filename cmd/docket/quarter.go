package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zcook44/burden-of-proof/internal/batch"
	"github.com/zcook44/burden-of-proof/internal/config"
)

// runQuarter is the quarterly operator wrapper.
// It fails closed on tailoring errors, dry-runs the configured platforms, then
// writes unless --dry-run is set. A platform with no inputs is skipped.
// --rhel and --cisco select one platform. Paths come from flags, then the
// environment, then the shared config file. The first failing step stops the command.
func runQuarter(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("quarter", flag.ContinueOnError)
	flags.SetOutput(stderr)
	libraryRoot := flags.String("library-root", "", "STIG library root")
	inputRoot := flags.String("input-root", "", "RHEL scan tree")
	evidenceRoot := flags.String("evidence-root", "", "Cisco evidence tree")
	manifest := flags.String("manifest", "", "Cisco device manifest")
	outputRoot := flags.String("output-root", "", "Cisco checklist output")
	rhelOnly := flags.Bool("rhel", false, "convert RHEL scans only")
	ciscoOnly := flags.Bool("cisco", false, "convert Cisco evidence only")
	dryRun := flags.Bool("dry-run", false, "validate and preview; do not write checklists")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	if flags.NArg() != 0 || (*rhelOnly && *ciscoOnly) {
		fmt.Fprintln(stderr, "usage: docket quarter [--library-root DIR] [--input-root DIR] [--evidence-root DIR] [--manifest FILE] [--output-root DIR] [--rhel | --cisco] [--dry-run]")
		return 2
	}
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "quarter: %v\n", err)
		return 2
	}
	*libraryRoot = config.Resolve(*libraryRoot, "DOCKET_LIBRARY_ROOT", cfg.LibraryRoot, "")
	*inputRoot = config.Resolve(*inputRoot, "DOCKET_INPUT_ROOT", cfg.InputRoot, "")
	*evidenceRoot = config.Resolve(*evidenceRoot, "DOCKET_EVIDENCE_ROOT", cfg.EvidenceRoot, "")
	*manifest = config.Resolve(*manifest, "DOCKET_CISCO_MANIFEST", cfg.CiscoManifest, "")
	*outputRoot = config.Resolve(*outputRoot, "DOCKET_OUTPUT_ROOT", cfg.OutputRoot, "")
	if *libraryRoot == "" {
		fmt.Fprintln(stderr, "quarter: library root is required (flag, DOCKET_LIBRARY_ROOT, or config library_root)")
		return 2
	}
	for _, path := range []*string{libraryRoot, inputRoot, evidenceRoot, manifest, outputRoot} {
		if *path == "" {
			continue
		}
		absolute, absErr := filepath.Abs(*path)
		if absErr != nil {
			fmt.Fprintf(stderr, "quarter: %v\n", absErr)
			return 2
		}
		*path = absolute
	}

	runRHEL := !*ciscoOnly
	runCisco := !*rhelOnly
	if *ciscoOnly {
		fmt.Fprintln(out, "QUARTER skipping RHEL (--cisco)")
	}
	if *rhelOnly {
		fmt.Fprintln(out, "QUARTER skipping Cisco (--rhel)")
	}
	if runRHEL && *inputRoot == "" {
		if *rhelOnly {
			fmt.Fprintln(stderr, "quarter: --rhel needs an input root (flag, DOCKET_INPUT_ROOT, or config input_root)")
			return 2
		}
		fmt.Fprintln(out, "QUARTER skipping RHEL: no input root")
		runRHEL = false
	}
	ciscoFields := 0
	for _, path := range []string{*manifest, *evidenceRoot, *outputRoot} {
		if path != "" {
			ciscoFields++
		}
	}
	if runCisco {
		switch {
		case ciscoFields == 0:
			if *ciscoOnly {
				fmt.Fprintln(stderr, "quarter: --cisco needs manifest, evidence_root, and output_root")
				return 2
			}
			fmt.Fprintln(out, "QUARTER skipping Cisco: no manifest, evidence root, and output root")
			runCisco = false
		case ciscoFields < 3:
			fmt.Fprintln(stderr, "quarter: cisco-batch needs manifest, evidence_root and output_root together")
			return 2
		}
	}
	if runRHEL {
		info, statErr := os.Lstat(*inputRoot)
		if statErr != nil || !info.IsDir() {
			if *rhelOnly {
				fmt.Fprintf(stderr, "quarter: input root is not a directory: %s\n", *inputRoot)
				return 2
			}
			fmt.Fprintf(out, "QUARTER skipping RHEL: input root is not a directory (%s)\n", *inputRoot)
			runRHEL = false
		}
	}
	if !runRHEL && !runCisco {
		fmt.Fprintln(stderr, "quarter: nothing to convert. Set input_root for RHEL, or manifest, evidence_root and output_root for Cisco. Use --rhel or --cisco to select one platform.")
		return 2
	}

	fmt.Fprintln(out, "QUARTER tailoring check")
	checkArgs := []string{"--library-root", *libraryRoot}
	if runRHEL {
		checkArgs = append(checkArgs, "--scan-root", *inputRoot)
	}
	if code := runTailoringCheck(checkArgs, out, stderr); code != 0 {
		fmt.Fprintln(stderr, "quarter: tailoring check failed")
		fmt.Fprintln(stderr, "quarter: stopped at tailoring check. Fix the reported file and run the same command again. Nothing was written.")
		return code
	}
	if runCisco && *evidenceRoot != *inputRoot {
		fmt.Fprintln(out, "QUARTER tailoring check (cisco evidence)")
		if code := runTailoringCheck([]string{"--library-root", *libraryRoot, "--scan-root", *evidenceRoot}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: cisco tailoring check failed")
			fmt.Fprintln(stderr, "quarter: stopped at tailoring check. Fix the reported file and run the same command again. Nothing was written.")
			return code
		}
	}
	if runRHEL {
		count, countErr := rhelScanCount(*inputRoot)
		if countErr != nil {
			fmt.Fprintf(stderr, "quarter: %v\n", countErr)
			fmt.Fprintln(stderr, "quarter: stopped before writing. Fix the input root and run the same command again.")
			return 2
		}
		if count == 0 {
			if *rhelOnly {
				fmt.Fprintf(stderr, "quarter: no OpenSCAP scan bundles beneath %s\n", *inputRoot)
				return 2
			}
			fmt.Fprintf(out, "QUARTER skipping RHEL: no OpenSCAP scan bundles beneath %s\n", *inputRoot)
			runRHEL = false
		}
	}
	if !runRHEL && !runCisco {
		fmt.Fprintln(stderr, "quarter: nothing to convert after skipping empty platforms")
		return 2
	}

	if runRHEL {
		fmt.Fprintln(out, "QUARTER batch-cklb dry-run")
		if code := runBatch([]string{"--input-root", *inputRoot, "--library-root", *libraryRoot, "--dry-run"}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: batch-cklb dry-run failed")
			fmt.Fprintln(stderr, "quarter: stopped at the RHEL dry run. Nothing was written. Fix the reported scan and run the same command again.")
			return code
		}
	}
	if runCisco {
		fmt.Fprintln(out, "QUARTER cisco-batch dry-run")
		if code := runCiscoBatch([]string{"--manifest", *manifest, "--evidence-root", *evidenceRoot, "--library-root", *libraryRoot, "--output-root", *outputRoot, "--dry-run"}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: cisco-batch dry-run failed")
			fmt.Fprintln(stderr, "quarter: stopped at the Cisco dry run. Nothing was written. Fix the reported device and run the same command again.")
			return code
		}
	}
	if *dryRun {
		fmt.Fprintln(out, "QUARTER DRY RUN complete; no checklists written")
		return 0
	}
	if runRHEL {
		fmt.Fprintln(out, "QUARTER batch-cklb")
		if code := runBatch([]string{"--input-root", *inputRoot, "--library-root", *libraryRoot}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: batch-cklb failed")
			fmt.Fprintln(stderr, "quarter: stopped during the RHEL write. Run the same command again after fixing the reported scan. Identical checklists already written are skipped.")
			return code
		}
	}
	if runCisco {
		fmt.Fprintln(out, "QUARTER cisco-batch")
		if code := runCiscoBatch([]string{"--manifest", *manifest, "--evidence-root", *evidenceRoot, "--library-root", *libraryRoot, "--output-root", *outputRoot}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: cisco-batch failed")
			fmt.Fprintln(stderr, "quarter: stopped during the Cisco write. RHEL checklists from this run stay in place. Run the same command again after fixing the reported device. Identical checklists are skipped.")
			return code
		}
	}
	fmt.Fprintln(out, "QUARTER complete")
	return 0
}

func rhelScanCount(root string) (int, error) {
	scans, err := batch.Discover(root)
	if err != nil {
		if strings.Contains(err.Error(), "no OpenSCAP scan bundles") {
			return 0, nil
		}
		return 0, err
	}
	return len(scans), nil
}
