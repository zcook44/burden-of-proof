package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

func runTailoringCheck(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("tailoring check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	libraryRoot := flags.String("library-root", "", "owner-private STIG library root")
	scanRoot := flags.String("scan-root", "", "owner-private scan root with host directories (optional, for host-layer validation)")
	benchmarkPath := flags.String("benchmark", "", "explicit RHEL benchmark (instead of --library-root)")
	scanDir := flags.String("scan-dir", "", "single host scan directory (with --benchmark)")
	
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: docket tailoring check --library-root DIR [--scan-root DIR]")
		fmt.Fprintln(stderr, "   or: docket tailoring check --benchmark FILE --scan-dir DIR")
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
	
	if *benchmarkPath != "" && *scanRoot != "" {
		fmt.Fprintln(stderr, "tailoring check: --scan-root requires --library-root, not --benchmark")
		return 2
	}
	
	// Make paths absolute
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
	
	issues := 0
	warnings := 0
	
	if *libraryRoot != "" {
		// Check library root tailoring files
		i, w := checkLibraryTailoring(*libraryRoot, out, stderr)
		issues += i
		warnings += w
		
		// Check scan root for host overrides if provided
		if *scanRoot != "" {
			i, w := checkScanRootTailoring(*libraryRoot, *scanRoot, out, stderr)
			issues += i
			warnings += w
		}
	} else {
		// Single benchmark + single scan directory
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

func checkLibraryTailoring(libraryRoot string, out, stderr io.Writer) (int, int) {
	issues := 0
	warnings := 0
	
	fmt.Fprintf(out, "Checking library root: %s\n", libraryRoot)
	
	// Find all .tailoring.yaml files in library root (not recursive)
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
		
		// Try to find matching benchmark
		benchmarkPath := ""
		var benchmark []byte
		
		// For RHEL: look for RHEL_X_STIG benchmarks
		if strings.HasPrefix(benchmarkID, "RHEL_") && strings.HasSuffix(benchmarkID, "_STIG") {
			// Search for matching RHEL benchmark in library
			pattern := "U_" + benchmarkID + "*.xml"
			matches, _ := filepath.Glob(filepath.Join(libraryRoot, pattern))
			if len(matches) > 0 {
				benchmarkPath = matches[0]
				benchmark, _ = readPrivate(benchmarkPath)
			}
		}
		
		// For Cisco: try to find benchmark
		if strings.HasPrefix(benchmarkID, "Cisco_") && strings.HasSuffix(benchmarkID, "_STIG") {
			pattern := "U_" + strings.ReplaceAll(benchmarkID, "_", "_*") + "*Manual-xccdf.xml"
			matches, _ := filepath.Glob(filepath.Join(libraryRoot, pattern))
			if len(matches) > 0 {
				benchmarkPath = matches[0]
				benchmark, _ = readPrivate(benchmarkPath)
			}
		}
		
		if benchmarkPath == "" {
			fmt.Fprintf(stderr, "WARNING: %s: no matching benchmark found in library\n", entry.Name())
			warnings++
			continue
		}
		
		// Try to load and validate the tailoring file
		// We need a minimal report to validate
		scan := []byte(`<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult><rule-result idref="dummy"><result>pass</result></rule-result></TestResult></Benchmark>`)
		report, err := reconcile.Convert(scan, benchmark)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: cannot build report from benchmark: %v\n", entry.Name(), err)
			issues++
			continue
		}
		
		// Infer if Cisco (requires full inventory) from benchmark ID
		requireFullInventory := strings.HasPrefix(benchmarkID, "Cisco_") && strings.HasSuffix(benchmarkID, "_STIG")
		_, _, err = loadTailoringLayer(tailoringPath, benchmarkID, benchmark, report, "root", requireFullInventory)
		if err != nil {
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
	issues := 0
	warnings := 0
	
	fmt.Fprintf(out, "\nChecking scan root: %s\n", scanRoot)
	
	// Walk scan root to find host directories with tailoring files
	err := filepath.WalkDir(scanRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tailoring.yaml") {
			return nil
		}
		
		// This is a host-level tailoring file
		hostDir := filepath.Dir(path)
		benchmarkID := strings.TrimSuffix(entry.Name(), ".tailoring.yaml")
		
		fmt.Fprintf(out, "Checking host override: %s (host: %s)\n", entry.Name(), filepath.Base(hostDir))
		
		// Find matching benchmark in library
		benchmarkPath := ""
		var benchmark []byte
		
		if strings.HasPrefix(benchmarkID, "RHEL_") && strings.HasSuffix(benchmarkID, "_STIG") {
			pattern := "U_" + benchmarkID + "*.xml"
			matches, _ := filepath.Glob(filepath.Join(libraryRoot, pattern))
			if len(matches) > 0 {
				benchmarkPath = matches[0]
				benchmark, _ = readPrivate(benchmarkPath)
			}
		}
		
		if strings.HasPrefix(benchmarkID, "Cisco_") && strings.HasSuffix(benchmarkID, "_STIG") {
			pattern := "U_" + strings.ReplaceAll(benchmarkID, "_", "_*") + "*Manual-xccdf.xml"
			matches, _ := filepath.Glob(filepath.Join(libraryRoot, pattern))
			if len(matches) > 0 {
				benchmarkPath = matches[0]
				benchmark, _ = readPrivate(benchmarkPath)
			}
		}
		
		if benchmarkPath == "" {
			fmt.Fprintf(stderr, "ERROR: %s: no matching benchmark found\n", path)
			issues++
			return nil
		}
		
		// Build minimal report
		scan := []byte(`<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult><rule-result idref="dummy"><result>pass</result></rule-result></TestResult></Benchmark>`)
		report, err := reconcile.Convert(scan, benchmark)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: cannot build report: %v\n", path, err)
			issues++
			return nil
		}
		
		// Host layer never requires full inventory (always partial)
		_, _, err = loadTailoringLayer(path, benchmarkID, benchmark, report, "host", false)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: validation failed: %v\n", path, err)
			issues++
		} else {
			fmt.Fprintf(out, "OK: %s (host layer)\n", path)
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
	issues := 0
	warnings := 0
	
	fmt.Fprintf(out, "Checking benchmark: %s\n", benchmarkPath)
	fmt.Fprintf(out, "Checking scan directory: %s\n", scanDir)
	
	benchmark, err := readPrivate(benchmarkPath)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: cannot read benchmark: %v\n", err)
		return 1, 0
	}
	
	// Infer benchmark ID from path or content
	benchmarkID := ""
	// For RHEL: extract from filename or scan
	// For Cisco: extract from XML
	
	// This is a simplified check - in production we'd need proper ID extraction
	base := filepath.Base(benchmarkPath)
	if strings.Contains(base, "RHEL_") {
		// Try to extract RHEL_X_STIG from filename
		for _, part := range []string{"RHEL_7_STIG", "RHEL_8_STIG", "RHEL_9_STIG", "RHEL_10_STIG"} {
			if strings.Contains(base, part) {
				benchmarkID = part
				break
			}
		}
	}
	
	if benchmarkID == "" {
		fmt.Fprintf(stderr, "ERROR: cannot determine benchmark ID from %s\n", benchmarkPath)
		return 1, 0
	}
	
	libraryDir := filepath.Dir(benchmarkPath)
	rootPath := filepath.Join(libraryDir, benchmarkID+".tailoring.yaml")
	hostPath := filepath.Join(scanDir, benchmarkID+".tailoring.yaml")
	
	// Build minimal report
	scan := []byte(`<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult><rule-result idref="dummy"><result>pass</result></rule-result></TestResult></Benchmark>`)
	report, err := reconcile.Convert(scan, benchmark)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: cannot build report from benchmark: %v\n", err)
		return 1, 0
	}
	
	// Check root layer
	if _, err := os.Lstat(rootPath); err == nil {
		// Infer if Cisco (requires full inventory) from benchmark ID
		requireFullInventory := strings.HasPrefix(benchmarkID, "Cisco_") && strings.HasSuffix(benchmarkID, "_STIG")
		_, _, err := loadTailoringLayer(rootPath, benchmarkID, benchmark, report, "root", requireFullInventory)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: validation failed: %v\n", rootPath, err)
			issues++
		} else {
			fmt.Fprintf(out, "OK: %s (root layer)\n", rootPath)
		}
	}
	
	// Check host layer
	if _, err := os.Lstat(hostPath); err == nil {
		// Host layer never requires full inventory (always partial)
		_, _, err := loadTailoringLayer(hostPath, benchmarkID, benchmark, report, "host", false)
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: %s: validation failed: %v\n", hostPath, err)
			issues++
		} else {
			fmt.Fprintf(out, "OK: %s (host layer)\n", hostPath)
		}
	}
	
	if issues == 0 {
		fmt.Fprintf(out, "No tailoring validation issues found\n")
	}
	
	return issues, warnings
}
