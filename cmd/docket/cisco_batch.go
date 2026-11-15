package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/zcook44/burden-of-proof/internal/ciscoconfig"
	"github.com/zcook44/burden-of-proof/internal/draft"
)

type reviewManifest struct {
	SchemaVersion int            `json:"schema_version"`
	Devices       []reviewDevice `json:"devices"`
}

type reviewDevice struct {
	Host       string   `json:"host"`
	Platform   string   `json:"platform"`
	Benchmarks []string `json:"benchmarks"`
}

func readPortRoles(path string) (ciscoconfig.RoleTable, []byte, error) {
	if path == "" {
		return ciscoconfig.RoleTable{}, nil, nil
	}
	data, err := readPrivate(path)
	if err != nil {
		return ciscoconfig.RoleTable{}, nil, err
	}
	roles, err := ciscoconfig.ParsePortRoles(data)
	if err != nil {
		return ciscoconfig.RoleTable{}, nil, err
	}
	return roles, data, nil
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func platformAllowsBenchmark(platform, benchmarkID string) bool {
	xe := strings.Contains(benchmarkID, "IOS-XE") || strings.Contains(benchmarkID, "IOS_XE")
	nx := strings.Contains(benchmarkID, "NX-OS") || strings.Contains(benchmarkID, "NXOS")
	switch platform {
	case "ios-xe":
		return xe
	case "nxos":
		return nx
	case "ios":
		return strings.Contains(benchmarkID, "IOS") && !xe && !nx
	default:
		return false
	}
}

func runCiscoBatch(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("cisco-batch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "device manifest JSON")
	evidenceRoot := flags.String("evidence-root", "", "directory of host/scan.running-config trees")
	libraryRoot := flags.String("library-root", "", "owner-private Cisco manual XCCDF library")
	outputRoot := flags.String("output-root", "", "private directory for one checklist folder per benchmark")
	dryRun := flags.Bool("dry-run", false, "score and print counts without writing")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	if flags.NArg() != 0 || *manifestPath == "" || *evidenceRoot == "" || *libraryRoot == "" || *outputRoot == "" {
		fmt.Fprintln(stderr, "usage: docket cisco-batch --manifest FILE --evidence-root DIR --library-root DIR --output-root DIR [--dry-run]")
		return 2
	}
	for _, path := range []*string{manifestPath, evidenceRoot, libraryRoot, outputRoot} {
		absolute, err := filepath.Abs(*path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		*path = absolute
	}
	manifestBytes, err := readPrivate(*manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "Cisco manifest: %v\n", err)
		return 2
	}
	var manifest reviewManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || manifest.SchemaVersion != 1 || len(manifest.Devices) == 0 {
		fmt.Fprintf(stderr, "Cisco manifest: schema_version 1 and a devices list are required\n")
		return 2
	}
	if err := privateLibraryDirectory(*evidenceRoot); err != nil || privateLibraryDirectory(*libraryRoot) != nil {
		if err == nil {
			err = privateLibraryDirectory(*libraryRoot)
		}
		fmt.Fprintf(stderr, "Cisco batch: %v\n", err)
		return 2
	}
	var built []reviewLink
	for _, device := range manifest.Devices {
		if !safeTarget.MatchString(device.Host) || strings.Contains(device.Host, "..") || len(device.Benchmarks) == 0 {
			fmt.Fprintf(stderr, "Cisco batch: invalid device %q\n", device.Host)
			return 2
		}
		hostDir := filepath.Join(*evidenceRoot, device.Host)
		configPath := filepath.Join(hostDir, "scan.running-config")
		if filepath.Base(filepath.Dir(configPath)) != device.Host {
			fmt.Fprintf(stderr, "Cisco batch: config path escaped %s\n", device.Host)
			return 2
		}
		config, err := readPrivate(configPath)
		if err != nil {
			fmt.Fprintf(stderr, "Cisco batch: %v\n", err)
			return 2
		}
		if len(config) == 0 || len(config) > 8<<20 || !utf8Valid(config) {
			fmt.Fprintf(stderr, "Cisco batch: %s configuration must be nonempty UTF-8 text at most 8 MiB\n", device.Host)
			return 2
		}
		parsed, err := ciscoconfig.Parse(config)
		if err != nil {
			fmt.Fprintf(stderr, "Cisco batch: %s: %v\n", device.Host, err)
			return 2
		}
		if parsed.Hostname != device.Host {
			fmt.Fprintf(stderr, "Cisco batch: %s hostname command is %q\n", device.Host, parsed.Hostname)
			return 2
		}
		rolePath := filepath.Join(hostDir, "port-roles.csv")
		roles := ciscoconfig.RoleTable{}
		var roleBytes []byte
		if _, statErr := os.Lstat(rolePath); statErr == nil {
			roles, roleBytes, err = readPortRoles(rolePath)
			if err != nil {
				fmt.Fprintf(stderr, "Cisco batch: %s: %v\n", device.Host, err)
				return 2
			}
			if unknown := ciscoconfig.UnknownInterfaces(parsed, roles); len(unknown) > 0 {
				fmt.Fprintf(stderr, "Cisco batch: %s port-role table names interfaces that are not in the configuration: %s\n", device.Host, strings.Join(unknown, ", "))
				return 2
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			fmt.Fprintf(stderr, "Cisco batch: %s port roles: %v\n", device.Host, statErr)
			return 2
		}
		seen := map[string]bool{}
		for _, benchmarkID := range device.Benchmarks {
			if seen[benchmarkID] || !ciscoID.MatchString(benchmarkID) || !platformAllowsBenchmark(device.Platform, benchmarkID) {
				fmt.Fprintf(stderr, "Cisco batch: %s platform %s cannot use benchmark %s\n", device.Host, device.Platform, benchmarkID)
				return 2
			}
			seen[benchmarkID] = true
			benchmarkPath, benchmark, err := selectCiscoBenchmark(*libraryRoot, benchmarkID)
			if err != nil {
				fmt.Fprintf(stderr, "Cisco batch: %v\n", err)
				return 2
			}
			doc, err := draft.BuildCiscoReview(config, device.Host, benchmark, roles)
			if err != nil {
				fmt.Fprintf(stderr, "Cisco batch: %s %s: %v\n", device.Host, benchmarkID, err)
				return 2
			}
			suggestion, err := suggestCiscoTailoring(benchmarkID, benchmark, doc)
			if err != nil {
				fmt.Fprintf(stderr, "Cisco tailoring suggestion: %v\n", err)
				return 2
			}
			policyDir := ciscoPolicyDirectory(hostDir, filepath.Dir(benchmarkPath), benchmarkID)
			policyRules, policyPath, policyBytes, err := loadCiscoTailoring(policyDir, benchmarkID, benchmark, doc)
			if err != nil {
				fmt.Fprintf(stderr, "Cisco tailoring: %v\n", err)
				return 2
			}
			if policyPath != "" {
				doc["id"] = draft.CiscoTailoredID(doc["id"].(string), sha256Hex(policyBytes))
				_ = applyCiscoTailoring(doc, policyRules)
			}
			counts := map[string]int{}
			for _, item := range doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any) {
				counts[item.(map[string]any)["status"].(string)]++
			}
			fmt.Fprintf(out, "BENCHMARK %s %s open=%d not_a_finding=%d not_applicable=%d not_reviewed=%d\n", device.Host, benchmarkID, counts["open"], counts["not_a_finding"], counts["not_applicable"], counts["not_reviewed"])
			body, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			body = append(body, '\n')
			if *dryRun {
				continue
			}
			digestParts := [][]byte{[]byte(draft.CiscoConfigEvaluatorVersion), config, benchmark, []byte(device.Host)}
			if len(roleBytes) > 0 {
				digestParts = append(digestParts, roleBytes)
			}
			if len(policyBytes) > 0 {
				digestParts = append(digestParts, policyBytes)
			}
			digest := bundleDigest(digestParts...)
			dir := filepath.Join(*outputRoot, benchmarkID, device.Host)
			path := filepath.Join(dir, "scan-cisco-"+sha256Hex(benchmark)[:16]+"-"+digest[:16]+"-ASSESSMENT.cklb")
			record := map[string]any{
				"schema_version": 2, "checklist_sha256": sha256Hex(body),
				"mapping_method":    "config-only pinned checks; port roles required for topology controls; unsupported controls require human review",
				"evaluator_version": draft.CiscoConfigEvaluatorVersion, "status_counts": counts,
				"config":    evidenceInput{configPath, sha256Hex(config)},
				"benchmark": evidenceInput{benchmarkPath, sha256Hex(benchmark)},
				"target":    device.Host, "benchmark_id": benchmarkID,
				"platform":        device.Platform,
				"config_hostname": parsed.Hostname, "config_complete": parsed.Complete(ciscoconfig.Family(benchmarkID)),
			}
			if len(roleBytes) > 0 {
				record["port_roles"] = evidenceInput{rolePath, sha256Hex(roleBytes)}
			}
			if policyPath != "" {
				record["schema_version"] = 3
				record["tailoring"] = evidenceInput{policyPath, sha256Hex(policyBytes)}
			}
			sidecar, err := json.MarshalIndent(record, "", "  ")
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			sidecar = append(sidecar, '\n')
			page, err := reviewHTML(device.Host, benchmarkID, parsed.Complete(ciscoconfig.Family(benchmarkID)), strings.TrimSuffix(filepath.Base(path), ".cklb")+".tailoring.yaml", doc)
			if err != nil {
				fmt.Fprintf(stderr, "Cisco review page: %v\n", err)
				return 2
			}
			built = append(built, reviewLink{Host: device.Host, Benchmark: benchmarkID, Href: relLink(*outputRoot, strings.TrimSuffix(path, ".cklb")+".review.html"), Counts: counts, Complete: parsed.Complete(ciscoconfig.Family(benchmarkID))})
			if err := ensurePrivateDir(dir); err != nil {
				fmt.Fprintf(stderr, "Cisco batch output: %v\n", err)
				return 2
			}
			skipped, err := writeBatchResult(path, body)
			if err != nil {
				fmt.Fprintf(stderr, "Cisco checklist: %v\n", err)
				return 2
			}
			if _, err := writeBatchResult(path+".provenance.json", sidecar); err != nil {
				fmt.Fprintf(stderr, "Cisco provenance: %v\n", err)
				return 2
			}
			reviewPath := strings.TrimSuffix(path, ".cklb") + ".review.html"
			tailorPath := strings.TrimSuffix(path, ".cklb") + ".tailoring.yaml"
			if _, err := writeBatchResult(reviewPath, page); err != nil {
				fmt.Fprintf(stderr, "Cisco review page: %v\n", err)
				return 2
			}
			if _, err := writeBatchResult(tailorPath, suggestion); err != nil {
				fmt.Fprintf(stderr, "Cisco tailoring suggestion: %v\n", err)
				return 2
			}
			if skipped {
				fmt.Fprintf(out, "SKIP %s\n", reviewPath)
			} else {
				fmt.Fprintf(out, "CREATED %s\n", reviewPath)
			}
		}
	}
	if *dryRun {
		fmt.Fprintln(out, "DRY RUN no files written")
		return 0
	}
	index, err := reviewIndex(built)
	if err != nil {
		fmt.Fprintf(stderr, "Cisco review index: %v\n", err)
		return 2
	}
	if err := ensurePrivateDir(*outputRoot); err != nil {
		fmt.Fprintf(stderr, "Cisco batch output: %v\n", err)
		return 2
	}
	if _, err := writeBatchResult(filepath.Join(*outputRoot, "index.html"), index); err != nil {
		fmt.Fprintf(stderr, "Cisco review index: %v\n", err)
		return 2
	}
	fmt.Fprintf(out, "REVIEW %s (%d checklists)\n", filepath.Join(*outputRoot, "index.html"), len(built))
	return 0
}

func utf8Valid(data []byte) bool {
	return utf8.Valid(data) && !bytes.Contains(data, []byte{0})
}

func relLink(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}
