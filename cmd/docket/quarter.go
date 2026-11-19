package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/zcook44/burden-of-proof/internal/config"
)

// runQuarter is the quarterly operator wrapper.
// It fails closed on tailoring errors, dry-runs both converters, then writes
// unless --dry-run is set. Paths come from flags, then the environment, then
// the shared config file.
func runQuarter(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("quarter", flag.ContinueOnError)
	flags.SetOutput(stderr)
	libraryRoot := flags.String("library-root", "", "STIG library root")
	inputRoot := flags.String("input-root", "", "RHEL scan tree")
	evidenceRoot := flags.String("evidence-root", "", "Cisco evidence tree")
	manifest := flags.String("manifest", "", "Cisco device manifest")
	outputRoot := flags.String("output-root", "", "Cisco checklist output")
	dryRun := flags.Bool("dry-run", false, "validate and preview; do not write checklists")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: docket quarter [--library-root DIR] [--input-root DIR] [--evidence-root DIR] [--manifest FILE] [--output-root DIR] [--dry-run]")
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
	if *inputRoot == "" && (*manifest == "" || *evidenceRoot == "" || *outputRoot == "") {
		fmt.Fprintln(stderr, "quarter: set input_root for RHEL, or manifest, evidence_root and output_root for Cisco")
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
	fmt.Fprintln(out, "QUARTER tailoring check")
	checkArgs := []string{"--library-root", *libraryRoot}
	if *inputRoot != "" {
		checkArgs = append(checkArgs, "--scan-root", *inputRoot)
	}
	if code := runTailoringCheck(checkArgs, out, stderr); code != 0 {
		fmt.Fprintln(stderr, "quarter: tailoring check failed")
		return code
	}
	if *evidenceRoot != "" && *evidenceRoot != *inputRoot {
		fmt.Fprintln(out, "QUARTER tailoring check (cisco evidence)")
		if code := runTailoringCheck([]string{"--library-root", *libraryRoot, "--scan-root", *evidenceRoot}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: cisco tailoring check failed")
			return code
		}
	}
	if *inputRoot != "" {
		fmt.Fprintln(out, "QUARTER batch-cklb dry-run")
		if code := runBatch([]string{"--input-root", *inputRoot, "--library-root", *libraryRoot, "--dry-run"}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: batch-cklb dry-run failed")
			return code
		}
	}
	cisco := *manifest != "" && *evidenceRoot != "" && *outputRoot != ""
	if cisco {
		fmt.Fprintln(out, "QUARTER cisco-batch dry-run")
		if code := runCiscoBatch([]string{"--manifest", *manifest, "--evidence-root", *evidenceRoot, "--library-root", *libraryRoot, "--output-root", *outputRoot, "--dry-run"}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: cisco-batch dry-run failed")
			return code
		}
	} else if *manifest != "" || *evidenceRoot != "" || *outputRoot != "" {
		fmt.Fprintln(stderr, "quarter: cisco-batch needs manifest, evidence_root and output_root together")
		return 2
	}
	if *dryRun {
		fmt.Fprintln(out, "QUARTER DRY RUN complete; no checklists written")
		return 0
	}
	if *inputRoot != "" {
		fmt.Fprintln(out, "QUARTER batch-cklb")
		if code := runBatch([]string{"--input-root", *inputRoot, "--library-root", *libraryRoot}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: batch-cklb failed")
			return code
		}
	}
	if cisco {
		fmt.Fprintln(out, "QUARTER cisco-batch")
		if code := runCiscoBatch([]string{"--manifest", *manifest, "--evidence-root", *evidenceRoot, "--library-root", *libraryRoot, "--output-root", *outputRoot}, out, stderr); code != 0 {
			fmt.Fprintln(stderr, "quarter: cisco-batch failed")
			return code
		}
	}
	fmt.Fprintln(out, "QUARTER complete")
	return 0
}
