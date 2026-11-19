// docket creates private review candidates; signed release is unsupported.
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
	return readFile(path, true)
}

// readBenchmark reads a DISA manual XCCDF. Those files are public publications,
// so they do not have to be mode 0600 or owned by the caller. Symlinks are
// still refused. Private evidence, tailoring, and outputs keep readPrivate.
func readBenchmark(path string) ([]byte, error) {
	return readFile(path, false)
}

func readFile(path string, ownerPrivate bool) ([]byte, error) {
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
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	if ownerPrivate && (stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0) {
		return nil, fmt.Errorf("%s must be an owner-private regular file", path)
	}
	return io.ReadAll(file)
}

func run(args []string, out, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "cisco-cklb" {
		return runCisco(args[1:], out, stderr)
	}
	if len(args) > 0 && args[0] == "cisco-batch" {
		return runCiscoBatch(args[1:], out, stderr)
	}
	if len(args) > 0 && args[0] == "cisco-xccdf" {
		return runCiscoXCCDF(args[1:], out, stderr)
	}
	if len(args) > 0 && args[0] == "xccdf-cklb" {
		return runXCCDFCKLB(args[1:], out, stderr)
	}
	if len(args) > 0 && args[0] == "batch-cklb" {
		return runBatch(args[1:], out, stderr)
	}
	if len(args) > 0 && args[0] == "reconcile" {
		return runMapped(args[1:], false, out, stderr)
	}
	if len(args) > 0 && args[0] == "draft-cklb" {
		return runMapped(args[1:], true, out, stderr)
	}
	if len(args) > 0 && args[0] == "tailoring" {
		if len(args) < 2 {
			fmt.Fprintln(stderr, "usage: docket tailoring {check|rehash|migrate}")
			return 2
		}
		switch args[1] {
		case "check":
			return runTailoringCheck(args[2:], out, stderr)
		case "rehash":
			return runTailoringRehash(args[2:], out, stderr)
		case "migrate":
			return runTailoringMigrate(args[2:], out, stderr)
		default:
			fmt.Fprintln(stderr, "usage: docket tailoring {check|rehash|migrate}")
			return 2
		}
	}
	if len(args) > 0 && args[0] == "quarter" {
		return runQuarter(args[1:], out, stderr)
	}
	if len(args) == 0 || args[0] != "asset-check" {
		fmt.Fprintln(stderr, "usage: docket {asset-check|reconcile|draft-cklb|batch-cklb|cisco-cklb|cisco-batch|cisco-xccdf|xccdf-cklb|tailoring check|tailoring rehash|tailoring migrate|quarter} (read-only checks or private review candidates; not a CKLB release)")
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
		fmt.Fprintf(stderr, "docket: %v\n", err)
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
			fmt.Fprintf(stderr, "docket: input path: %v\n", err)
			return 2
		}
		*input = absolute
	}
	scan, err := readPrivate(*scanPath)
	if err != nil {
		fmt.Fprintf(stderr, "docket: %v\n", err)
		return 2
	}
	benchmark, err := readBenchmark(*benchmarkPath)
	if err != nil {
		fmt.Fprintf(stderr, "docket: %v\n", err)
		return 2
	}
	report, err := reconcile.Convert(scan, benchmark)
	if err != nil {
		fmt.Fprintf(stderr, "docket: %v\n", err)
		return 2
	}

	// Load layered tailoring for draft-cklb (reconcile doesn't need it)
	var tailoring []layeredTailoringRule
	var rootPath, hostPath string
	var rootBytes, hostBytes []byte
	if asDraft {
		libraryDir := filepath.Dir(*benchmarkPath)
		hostDir := filepath.Dir(*scanPath)
		// RHEL root layer is partial (only overrides), not full inventory
		tailoring, rootPath, rootBytes, hostPath, hostBytes, err = loadLayeredTailoring(
			libraryDir, hostDir, report.DISABenchmark, benchmark, report)
		if err != nil {
			fmt.Fprintf(stderr, "docket: tailoring: %v\n", err)
			return 2
		}
	}

	var value any = report
	var htmlReport, arfBytes []byte
	if asDraft {
		if filepath.Ext(*outPath) != ".cklb" {
			fmt.Fprintln(stderr, "docket: draft output must have .cklb extension")
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
			fmt.Fprintf(stderr, "docket: draft rejected: %v\n", err)
			return 2
		}

		// Apply layered tailoring to draft
		if len(tailoring) > 0 {
			doc := value.(map[string]any)
			_, err = applyLayeredTailoring(doc, report, tailoring, rootPath, hostPath)
			if err != nil {
				fmt.Fprintf(stderr, "docket: tailoring application: %v\n", err)
				return 2
			}
		}
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "docket: %v\n", err)
		return 2
	}
	body = append(body, '\n')
	var provenance []byte
	if asDraft && *assessmentView {
		// Use layered provenance if tailoring was applied
		if len(tailoring) > 0 {
			// Extract rule origins from applied tailoring
			ruleOrigins := make(map[string]string)
			for _, rule := range tailoring {
				if rule.Status != "auto" {
					ruleOrigins[rule.STIGID] = rule.Origin
				}
			}
			tailorProv := &tailoringProvenance{
				RuleOrigins: ruleOrigins,
			}
			if rootPath != "" {
				tailorProv.RootFile = rootPath
				tailorProv.RootSHA256 = sha256Hex(rootBytes)
			}
			if hostPath != "" {
				tailorProv.HostFile = hostPath
				tailorProv.HostSHA256 = sha256Hex(hostBytes)
			}
			provenance, err = assessmentProvenanceLayered(body, report, *scanPath, *benchmarkPath, *htmlPath, *arfPath, htmlReport, arfBytes, tailorProv)
		} else {
			provenance, err = assessmentProvenance(body, report, *scanPath, *benchmarkPath, *htmlPath, *arfPath, htmlReport, arfBytes)
		}
		if err != nil {
			fmt.Fprintf(stderr, "docket: provenance rejected: %v\n", err)
			return 2
		}
	}
	parent := filepath.Dir(*outPath)
	parentFD, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintf(stderr, "docket: private output directory unavailable: %v\n", err)
		return 2
	}
	defer syscall.Close(parentFD)
	var info syscall.Stat_t
	if err = syscall.Fstat(parentFD, &info); err != nil || info.Uid != uint32(os.Geteuid()) || info.Mode&077 != 0 {
		fmt.Fprintln(stderr, "docket: output parent must be owner-private")
		return 2
	}
	name := filepath.Base(*outPath)
	if name == "." || name == ".." || name == "" {
		fmt.Fprintln(stderr, "docket: invalid output name")
		return 2
	}
	fd, err := syscall.Openat(parentFD, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		fmt.Fprintf(stderr, "docket: output must not exist: %v\n", err)
		return 2
	}
	file := os.NewFile(uintptr(fd), name)
	_, err = file.Write(body)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		fmt.Fprintf(stderr, "docket: incomplete output, inspect before retrying: %v\n", err)
		return 2
	}
	if provenance != nil {
		if _, err := writeBatchResult(*outPath+".provenance.json", provenance); err != nil {
			fmt.Fprintf(stderr, "docket: provenance sidecar failed: %v (checklist retained for safe inspection)\n", err)
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
