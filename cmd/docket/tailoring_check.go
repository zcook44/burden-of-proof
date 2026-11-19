package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zcook44/burden-of-proof/internal/config"
	"github.com/zcook44/burden-of-proof/internal/reconcile"
	"github.com/zcook44/burden-of-proof/internal/stigxml"
)

func runTailoringCheck(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("tailoring check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	libraryRoot := flags.String("library-root", "", "STIG library root (root tailoring and manuals)")
	scanRoot := flags.String("scan-root", "", "scan or evidence root with host tailoring (optional)")
	benchmarkPath := flags.String("benchmark", "", "explicit benchmark (instead of --library-root)")
	scanDir := flags.String("scan-dir", "", "single host directory (with --benchmark)")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	cfg, _, cfgErr := config.Load()
	if cfgErr != nil {
		fmt.Fprintf(stderr, "tailoring check: %v\n", cfgErr)
		return 2
	}
	if *benchmarkPath == "" {
		*libraryRoot = config.Resolve(*libraryRoot, "DOCKET_LIBRARY_ROOT", cfg.LibraryRoot, "")
	}
	scanFromFlag := *scanRoot != ""
	*scanRoot = config.Resolve(*scanRoot, "DOCKET_INPUT_ROOT", cfg.InputRoot, "")
	if *scanRoot != "" && !scanFromFlag {
		if st, statErr := os.Stat(*scanRoot); statErr != nil || !st.IsDir() {
			fmt.Fprintf(stderr, "tailoring check: scan root %s is not a directory yet; not checking host files\n", *scanRoot)
			*scanRoot = ""
		}
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: docket tailoring check --library-root DIR [--scan-root DIR]")
		fmt.Fprintln(stderr, "   or: docket tailoring check --benchmark FILE [--scan-dir DIR]")
		return 2
	}
	if (*libraryRoot == "") == (*benchmarkPath == "") {
		fmt.Fprintln(stderr, "tailoring check: specify either --library-root or --benchmark")
		return 2
	}
	if *libraryRoot != "" && *scanDir != "" {
		fmt.Fprintln(stderr, "tailoring check: --scan-dir requires --benchmark, not --library-root")
		return 2
	}
	if *benchmarkPath != "" && *scanRoot != "" && *scanDir != "" {
		fmt.Fprintln(stderr, "tailoring check: use one of --scan-root or --scan-dir")
		return 2
	}
	for _, path := range []*string{libraryRoot, scanRoot, benchmarkPath, scanDir} {
		if *path == "" {
			continue
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			fmt.Fprintf(stderr, "tailoring check: %v\n", err)
			return 2
		}
		*path = absolute
	}
	issues, warnings := 0, 0
	if *libraryRoot != "" {
		i, w := checkLibraryTailoring(*libraryRoot, out, stderr)
		issues += i
		warnings += w
		if *scanRoot != "" {
			i, w = checkScanRootTailoring(*libraryRoot, *scanRoot, out, stderr)
			issues += i
			warnings += w
		}
	} else {
		i, w := checkSingleBenchmarkTailoring(*benchmarkPath, *scanDir, out, stderr)
		issues += i
		warnings += w
	}
	if issues > 0 {
		fmt.Fprintf(out, "\nVALIDATION FAILED: %d issues, %d warnings\n", issues, warnings)
		return 2
	}
	fmt.Fprintf(out, "\nVALIDATION PASSED: no issues, %d warnings\n", warnings)
	return 0
}

func benchmarkForID(libraryRoot, benchmarkID string) (string, []byte, error) {
	if strings.HasPrefix(benchmarkID, "RHEL_") && strings.HasSuffix(benchmarkID, "_STIG") {
		major, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(benchmarkID, "RHEL_"), "_STIG"))
		if err != nil {
			return "", nil, fmt.Errorf("cannot read RHEL major from %s", benchmarkID)
		}
		return latestRHELRelease(libraryRoot, major)
	}
	if strings.HasPrefix(benchmarkID, "Cisco_") && strings.HasSuffix(benchmarkID, "_STIG") {
		return selectCiscoBenchmark(libraryRoot, benchmarkID)
	}
	return "", nil, fmt.Errorf("unsupported benchmark id %s", benchmarkID)
}

func reportForBenchmark(data []byte) (reconcile.Report, error) {
	id, controls, err := stigxml.Identities(data)
	if err != nil {
		return reconcile.Report{}, err
	}
	report := reconcile.Report{DISABenchmark: id, Controls: make([]reconcile.Control, 0, len(controls))}
	for group, rule := range controls {
		report.Controls = append(report.Controls, reconcile.Control{GroupID: group, RuleID: rule})
	}
	return report, nil
}

func checkLibraryTailoring(libraryRoot string, out, stderr io.Writer) (int, int) {
	issues, warnings := 0, 0
	fmt.Fprintf(out, "Checking library root: %s\n", libraryRoot)
	entries, err := os.ReadDir(libraryRoot)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: cannot read library root: %v\n", err)
		return 1, 0
	}
	found := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tailoring.yaml") {
			continue
		}
		found++
		tailoringPath := filepath.Join(libraryRoot, entry.Name())
		benchmarkID := strings.TrimSuffix(entry.Name(), ".tailoring.yaml")
		benchmarkPath, benchmark, err := benchmarkForID(libraryRoot, benchmarkID)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: no matching benchmark (%v)\n", entry.Name(), err)
			issues++
			continue
		}
		report, err := reportForBenchmark(benchmark)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: cannot read benchmark %s: %v\n", entry.Name(), benchmarkPath, err)
			issues++
			continue
		}
		if report.DISABenchmark != benchmarkID {
			fmt.Fprintf(stderr, "ERROR: %s: newest benchmark %s has id %s\n", entry.Name(), benchmarkPath, report.DISABenchmark)
			issues++
			continue
		}
		if _, _, err = loadTailoringLayer(tailoringPath, benchmarkID, benchmark, report, "root"); err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: validation failed: %v\n", entry.Name(), err)
			issues++
		} else {
			fmt.Fprintf(out, "OK: %s (root layer, %s)\n", entry.Name(), benchmarkPath)
		}
	}
	if found == 0 {
		fmt.Fprintf(out, "No tailoring files found in library root\n")
	}
	return issues, warnings
}

func checkScanRootTailoring(libraryRoot, scanRoot string, out, stderr io.Writer) (int, int) {
	issues, warnings := 0, 0
	fmt.Fprintf(out, "\nChecking scan root: %s\n", scanRoot)
	err := filepath.WalkDir(scanRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tailoring.yaml") {
			return nil
		}
		hostDir := filepath.Dir(path)
		benchmarkID := strings.TrimSuffix(entry.Name(), ".tailoring.yaml")
		fmt.Fprintf(out, "Checking host override: %s (host: %s)\n", entry.Name(), filepath.Base(hostDir))
		benchmarkPath, benchmark, err := benchmarkForID(libraryRoot, benchmarkID)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: no matching benchmark (%v)\n", path, err)
			issues++
			return nil
		}
		report, err := reportForBenchmark(benchmark)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: cannot read benchmark %s: %v\n", path, benchmarkPath, err)
			issues++
			return nil
		}
		if report.DISABenchmark != benchmarkID {
			fmt.Fprintf(stderr, "ERROR: %s: newest benchmark %s has id %s\n", path, benchmarkPath, report.DISABenchmark)
			issues++
			return nil
		}
		rootPath := filepath.Join(libraryRoot, benchmarkID+".tailoring.yaml")
		if _, statErr := os.Lstat(rootPath); statErr != nil {
			fmt.Fprintf(stderr, "WARNING: %s: host file has no root pin at %s\n", path, rootPath)
			warnings++
		}
		if _, _, err = loadTailoringLayer(path, benchmarkID, benchmark, report, "host"); err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: validation failed: %v\n", path, err)
			issues++
		} else {
			fmt.Fprintf(out, "OK: %s (host layer, benchmark %s)\n", path, benchmarkPath)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: scan root walk failed: %v\n", err)
		issues++
	}
	return issues, warnings
}

func checkSingleBenchmarkTailoring(benchmarkPath, scanDir string, out, stderr io.Writer) (int, int) {
	issues, warnings := 0, 0
	fmt.Fprintf(out, "Checking benchmark: %s\n", benchmarkPath)
	benchmark, err := readBenchmark(benchmarkPath)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: cannot read benchmark: %v\n", err)
		return 1, 0
	}
	report, err := reportForBenchmark(benchmark)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: cannot read benchmark: %v\n", err)
		return 1, 0
	}
	benchmarkID := report.DISABenchmark
	libraryDir := filepath.Dir(benchmarkPath)
	rootPath := filepath.Join(libraryDir, benchmarkID+".tailoring.yaml")
	if _, err := os.Lstat(rootPath); err == nil {
		if _, _, err := loadTailoringLayer(rootPath, benchmarkID, benchmark, report, "root"); err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: validation failed: %v\n", rootPath, err)
			issues++
		} else {
			fmt.Fprintf(out, "OK: %s (root layer)\n", rootPath)
		}
	}
	if scanDir != "" {
		hostPath := filepath.Join(scanDir, benchmarkID+".tailoring.yaml")
		if _, err := os.Lstat(hostPath); err == nil {
			if _, statErr := os.Lstat(rootPath); statErr != nil {
				fmt.Fprintf(stderr, "WARNING: %s: host file has no root pin\n", hostPath)
				warnings++
			}
			if _, _, err := loadTailoringLayer(hostPath, benchmarkID, benchmark, report, "host"); err != nil {
				fmt.Fprintf(stderr, "ERROR: %s: validation failed: %v\n", hostPath, err)
				issues++
			} else {
				fmt.Fprintf(out, "OK: %s (host layer)\n", hostPath)
			}
		}
	}
	return issues, warnings
}
