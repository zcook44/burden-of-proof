package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/zcook44/burden-of-proof/internal/batch"
	"github.com/zcook44/burden-of-proof/internal/draft"
	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

func bundleDigest(parts ...[]byte) string {
	h := sha256.New()
	for _, part := range parts {
		fmt.Fprintf(h, "%d:", len(part))
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeBatchResult uses a held owner-private directory, no-follow, and exclusive
// creation. Existing output may be skipped only when its complete bytes match.
func writeBatchResult(path string, body []byte) (bool, error) {
	fd, err := syscall.Open(filepath.Dir(path), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer syscall.Close(fd)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return false, err
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		return false, fmt.Errorf("output directory is not owner-private: %s", filepath.Dir(path))
	}
	name := filepath.Base(path)
	existing, err := readPrivate(path)
	if err == nil {
		if !bytes.Equal(existing, body) {
			return false, fmt.Errorf("existing output differs from current conversion: %s", path)
		}
		return true, nil
	}
	if !errors.Is(err, syscall.ENOENT) {
		return false, err
	}
	outfd, err := syscall.Openat(fd, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return false, fmt.Errorf("output must not exist: %w", err)
	}
	f := os.NewFile(uintptr(outfd), path)
	n, writeErr := f.Write(body)
	closeErr := f.Close()
	if writeErr == nil && n != len(body) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return false, fmt.Errorf("incomplete output %s: %w", path, writeErr)
	}
	return false, nil
}

func runBatch(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("batch-cklb", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("input-root", "", "owner-private directory to scan recursively")
	benchmarkPath := flags.String("benchmark", "", "explicit official DISA XCCDF benchmark (single OS; instead of --library-root)")
	libraryRoot := flags.String("library-root", "", "owner-private extracted STIG library; choose newest benchmark for each scan's RHEL OS")
	dryRun := flags.Bool("dry-run", false, "list complete bundles without converting or writing")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	if flags.NArg() != 0 || *root == "" || (*benchmarkPath == "") == (*libraryRoot == "") {
		fmt.Fprintln(stderr, "usage: stig-evidence batch-cklb --input-root PATH (--library-root DIR | --benchmark XCCDF) [--dry-run]")
		return 2
	}
	// Resolve caller-relative inputs once before discovery or benchmark selection.
	for _, input := range []*string{root, benchmarkPath, libraryRoot} {
		if *input == "" {
			continue
		}
		absolute, err := filepath.Abs(*input)
		if err != nil {
			fmt.Fprintf(stderr, "batch input path: %v\n", err)
			return 2
		}
		*input = absolute
	}
	scans, err := batch.Discover(*root)
	if err != nil {
		fmt.Fprintf(stderr, "batch: %v\n", err)
		return 2
	}
	type selection struct {
		path string
		data []byte
	}
	selected := map[int]selection{}
	if *benchmarkPath != "" {
		data, err := readPrivate(*benchmarkPath)
		if err != nil {
			fmt.Fprintf(stderr, "batch benchmark: %v\n", err)
			return 2
		}
		// The explicit benchmark's OS is checked by reconciliation for every scan.
		selected[0] = selection{*benchmarkPath, data}
	}
	created, skipped := 0, 0
	for _, s := range scans {
		scan, err := readPrivate(s.XCCDF)
		if err != nil {
			fmt.Fprintf(stderr, "batch %s: %v\n", s.XCCDF, err)
			return 2
		}
		major, err := reconcile.SourceFamily(scan)
		if err != nil {
			fmt.Fprintf(stderr, "batch %s: %v\n", s.XCCDF, err)
			return 2
		}
		choice, ok := selected[major]
		if *benchmarkPath != "" {
			choice = selected[0]
			ok = true
		}
		if !ok {
			path, data, err := latestBenchmark(*libraryRoot, scan)
			if err != nil {
				fmt.Fprintf(stderr, "batch benchmark for %s: %v\n", s.XCCDF, err)
				return 2
			}
			choice = selection{path, data}
			selected[major] = choice
		}
		fmt.Fprintf(out, "BENCHMARK RHEL %d: %s (sha256 %x)\n", major, choice.path, sha256.Sum256(choice.data))
		selectedPath, benchmark := choice.path, choice.data
		if *dryRun {
			kind := "XCCDF-only"
			if s.HTML != "" {
				kind = "HTML-only"
			}
			if s.ARF != "" {
				kind = "ARF+HTML"
			}
			fmt.Fprintf(out, "SCAN %s [%s]\n", s.XCCDF, kind)
			continue
		}
		var html []byte
		if s.HTML != "" {
			html, err = readPrivate(s.HTML)
			if err != nil {
				fmt.Fprintf(stderr, "batch %s: %v\n", s.HTML, err)
				return 2
			}
		}
		var arfBytes []byte
		if s.ARF != "" {
			arfBytes, err = readPrivate(s.ARF)
			if err != nil {
				fmt.Fprintf(stderr, "batch %s: %v\n", s.ARF, err)
				return 2
			}
		}
		report, err := reconcile.Convert(scan, benchmark)
		if err != nil {
			fmt.Fprintf(stderr, "batch %s: %v\n", s.XCCDF, err)
			return 2
		}
		// The target must agree with the host directory, not just with the HTML/ARF.
		if filepath.Base(s.Dir) != report.Target {
			fmt.Fprintf(stderr, "batch %s: target %q differs from directory %q\n", s.XCCDF, report.Target, s.Dir)
			return 2
		}
		var doc map[string]any
		if s.ARF != "" {
			doc, err = draft.BuildAssessmentWithARF(report, benchmark, html, arfBytes, false)
		} else if s.HTML != "" {
			doc, err = draft.BuildAssessmentWithReport(report, benchmark, html)
		} else {
			doc, err = draft.BuildMapped(report, benchmark)
		}
		if err != nil {
			fmt.Fprintf(stderr, "batch %s: %v\n", s.XCCDF, err)
			return 2
		}
		body, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "batch JSON %s: %v\n", s.XCCDF, err)
			return 2
		}
		body = append(body, '\n')
		name := s.Prefix + "-disa-" + report.BenchmarkSHA256[:16] + "-" + bundleDigest([]byte("assessment-provenance-v6"), scan, benchmark, html, arfBytes)[:16] + "-ASSESSMENT.cklb"
		path := filepath.Join(s.Dir, name)
		provenance, err := assessmentProvenance(body, report, s.XCCDF, selectedPath, s.HTML, s.ARF, html, arfBytes)
		if err != nil {
			fmt.Fprintf(stderr, "batch provenance %s: %v\n", s.XCCDF, err)
			return 2
		}
		wasSkipped, err := writeBatchResult(path, body)
		if err != nil {
			fmt.Fprintf(stderr, "batch %s: %v (created=%d skipped=%d)\n", s.XCCDF, err, created, skipped)
			return 2
		}
		if wasSkipped {
			// A prior run may have used a different private path for the same
			// benchmark or a different spelling of the scan root. Validate the
			// original paths and all non-path fields before retaining its sidecar.
			if old, readErr := readPrivate(path + ".provenance.json"); readErr == nil && equivalentProvenance(old, provenance) {
				skipped++
				fmt.Fprintf(out, "SKIP %s (verified equivalent provenance; original paths retained)\n", path)
				continue
			}
		}
		if _, err := writeBatchResult(path+".provenance.json", provenance); err != nil {
			fmt.Fprintf(stderr, "batch provenance %s: %v (checklist retained for safe retry)\n", path, err)
			return 2
		}
		if wasSkipped {
			skipped++
			fmt.Fprintf(out, "SKIP %s (verified identical)\n", path)
		} else {
			created++
			kind := "XCCDF-only"
			if s.HTML != "" {
				kind = "HTML-only"
			}
			if s.ARF != "" {
				kind = "ARF+HTML"
			}
			fmt.Fprintf(out, "CREATED %s (%d controls, %s)\n", path, len(report.Controls), kind)
		}
	}
	if *dryRun {
		fmt.Fprintf(out, "bundles: %d; no files written\n", len(scans))
		return 0
	}
	fmt.Fprintf(out, "complete: %d bundles; created=%d skipped=%d\n", len(scans), created, skipped)
	return 0
}
