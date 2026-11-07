// stig-evidence creates private review candidates; signed release is unsupported.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/zcook44/burden-of-proof/internal/asset"
	"github.com/zcook44/burden-of-proof/internal/draft"
	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

func readPrivate(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		return nil, fmt.Errorf("%s must be an owner-private regular file", path)
	}
	return io.ReadAll(file)
}

func run(args []string, out, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "batch-cklb" {
		return runBatch(args[1:], out, stderr)
	}
	if len(args) > 0 && args[0] == "reconcile" {
		return runMapped(args[1:], false, out, stderr)
	}
	if len(args) > 0 && args[0] == "draft-cklb" {
		return runMapped(args[1:], true, out, stderr)
	}
	if len(args) == 0 || args[0] != "asset-check" {
		fmt.Fprintln(stderr, "usage: stig-evidence asset-check --asset PATH --pre PATH --host FQDN (read-only; not a CKLB release)")
		return 2
	}
	flags := flag.NewFlagSet("asset-check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	assetPath := flags.String("asset", "", "asset record JSON")
	prePath := flags.String("pre", "", "pre-scan XML")
	host := flags.String("host", "", "exact asset FQDN")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *assetPath == "" || *prePath == "" || *host == "" {
		fmt.Fprintln(stderr, "asset-check requires --asset, --pre and --host with no positional arguments")
		return 2
	}
	record, err := readPrivate(*assetPath)
	if err == nil {
		var pre []byte
		pre, err = readPrivate(*prePath)
		if err == nil {
			err = asset.Validate(record, *host, pre)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "stig-evidence: %v\n", err)
		return 2
	}
	fmt.Fprintln(out, "asset record valid against supplied pre-scan bytes; provenance and baseline cleanliness not attested")
	return 0
}

func runMapped(args []string, asDraft bool, out, stderr io.Writer) int {
	command := "reconcile"
	if asDraft {
		command = "draft-cklb"
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	scanPath := flags.String("scan", "", "SSG XCCDF result")
	benchmarkPath := flags.String("benchmark", "", "official DISA RHEL 7/8/9/10 XCCDF benchmark matching the source OS")
	outPath := flags.String("out", "", "new private JSON report path")
	htmlPath := flags.String("html-report", "", "owner-private OpenSCAP HTML report with item-state evidence (draft only)")
	arfPath := flags.String("arf", "", "owner-private OpenSCAP ARF with collected OVAL item values (requires --html-report)")
	assessmentView := flags.Bool("assessment-view", false, "show executed checks and observed host values (requires --html-report; ARF adds collected values)")
	operatorApproved := flags.Bool("operator-approved", false, "caller attests operator approval; UNSIGNED, not a release (requires --assessment-view and --arf)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *scanPath == "" || *benchmarkPath == "" || *outPath == "" || (*htmlPath != "" && !asDraft) || (*arfPath != "" && *htmlPath == "") || (*assessmentView && *htmlPath == "") || (*operatorApproved && (!*assessmentView || *arfPath == "")) {
		fmt.Fprintln(stderr, "invalid flags: --assessment-view requires --html-report; --operator-approved requires --assessment-view and --arf; draft-cklb requires --scan, --benchmark and --out")
		return 2
	}
	for _, input := range []*string{scanPath, benchmarkPath, htmlPath, arfPath} {
		if *input == "" {
			continue
		}
		absolute, err := filepath.Abs(*input)
		if err != nil {
			fmt.Fprintf(stderr, "stig-evidence: input path: %v\n", err)
			return 2
		}
		*input = absolute
	}
	scan, err := readPrivate(*scanPath)
	if err != nil {
		fmt.Fprintf(stderr, "stig-evidence: %v\n", err)
		return 2
	}
	benchmark, err := readPrivate(*benchmarkPath)
	if err != nil {
		fmt.Fprintf(stderr, "stig-evidence: %v\n", err)
		return 2
	}
	report, err := reconcile.Convert(scan, benchmark)
	if err != nil {
		fmt.Fprintf(stderr, "stig-evidence: %v\n", err)
		return 2
	}
	var value any = report
	var htmlReport, arfBytes []byte
	if asDraft {
		if filepath.Ext(*outPath) != ".cklb" {
			fmt.Fprintln(stderr, "stig-evidence: draft output must have .cklb extension")
			return 2
		}
		if *arfPath != "" {
			htmlReport, err = readPrivate(*htmlPath)
			if err == nil {
				arfBytes, err = readPrivate(*arfPath)
			}
			if err == nil {
				if *assessmentView {
					value, err = draft.BuildAssessmentWithARF(report, benchmark, htmlReport, arfBytes, *operatorApproved)
				} else {
					value, err = draft.BuildWithARF(report, benchmark, htmlReport, arfBytes)
				}
			}
		} else if *htmlPath != "" {
			htmlReport, err = readPrivate(*htmlPath)
			if err == nil {
				if *assessmentView {
					value, err = draft.BuildAssessmentWithReport(report, benchmark, htmlReport)
				} else {
					value, err = draft.BuildWithReport(report, benchmark, htmlReport)
				}
			}
		} else {
			value, err = draft.BuildMapped(report, benchmark)
		}
		if err != nil {
			fmt.Fprintf(stderr, "stig-evidence: draft rejected: %v\n", err)
			return 2
		}
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "stig-evidence: %v\n", err)
		return 2
	}
	body = append(body, '\n')
	var provenance []byte
	if asDraft && *assessmentView {
		provenance, err = assessmentProvenance(body, report, *scanPath, *benchmarkPath, *htmlPath, *arfPath, htmlReport, arfBytes)
		if err != nil {
			fmt.Fprintf(stderr, "stig-evidence: provenance rejected: %v\n", err)
			return 2
		}
	}
	parent := filepath.Dir(*outPath)
	parentFD, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintf(stderr, "stig-evidence: private output directory unavailable: %v\n", err)
		return 2
	}
	defer syscall.Close(parentFD)
	var info syscall.Stat_t
	if err = syscall.Fstat(parentFD, &info); err != nil || info.Uid != uint32(os.Geteuid()) || info.Mode&077 != 0 {
		fmt.Fprintln(stderr, "stig-evidence: output parent must be owner-private")
		return 2
	}
	name := filepath.Base(*outPath)
	if name == "." || name == ".." || name == "" {
		fmt.Fprintln(stderr, "stig-evidence: invalid output name")
		return 2
	}
	fd, err := syscall.Openat(parentFD, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		fmt.Fprintf(stderr, "stig-evidence: output must not exist: %v\n", err)
		return 2
	}
	file := os.NewFile(uintptr(fd), name)
	_, err = file.Write(body)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		fmt.Fprintf(stderr, "stig-evidence: incomplete output, inspect before retrying: %v\n", err)
		return 2
	}
	if provenance != nil {
		if _, err := writeBatchResult(*outPath+".provenance.json", provenance); err != nil {
			fmt.Fprintf(stderr, "stig-evidence: provenance sidecar failed: %v (checklist retained for safe inspection)\n", err)
			return 2
		}
	}
	if asDraft {
		if *assessmentView {
			fmt.Fprintf(out, "ASSESSMENT VIEW CKLB (operator approval=%t, unsigned): %s (%d controls; numeric V/SV mapping; not signed evidence release)\n", *operatorApproved, *outPath, len(report.Controls))
		} else {
			fmt.Fprintf(out, "MAPPED DRAFT CKLB: %s (%d controls; numeric V/SV mapping, unresolved controls Not Reviewed; not a DISA scan or release)\n", *outPath, len(report.Controls))
		}
	} else {
		fmt.Fprintf(out, "candidate reconciliation: %s (%d official controls; not a DISA scan or CKLB)\n", *outPath, len(report.Controls))
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
