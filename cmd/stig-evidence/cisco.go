package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zcook44/burden-of-proof/internal/draft"
)

var ciscoID = regexp.MustCompile(`^Cisco_[A-Za-z0-9_-]+_STIG$`)
var safeTarget = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var ciscoFile = regexp.MustCompile(`^U_Cisco_[A-Za-z0-9_-]+_V([0-9]+)R([0-9]+)_(?:STIG_)?Manual-xccdf\.xml$`)

type ciscoMeta struct {
	XMLName xml.Name `xml:"Benchmark"`
	ID      string   `xml:"id,attr"`
	Version string   `xml:"version"`
	Plain   []struct {
		ID   string `xml:"id,attr"`
		Text string `xml:",chardata"`
	} `xml:"plain-text"`
}

// Validate the exact benchmark identity and release; an archive name alone is not evidence.
func validateCiscoBenchmark(data []byte, expectedID string) (int, int, error) {
	if bytes.Contains(data, []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
		return 0, 0, fmt.Errorf("DTD/entity forbidden")
	}
	var meta ciscoMeta
	if err := xml.Unmarshal(data, &meta); err != nil {
		return 0, 0, err
	}
	if !ciscoID.MatchString(expectedID) || meta.XMLName.Space != "http://checklists.nist.gov/xccdf/1.1" || meta.ID != expectedID {
		return 0, 0, fmt.Errorf("Cisco benchmark identity mismatch: wanted %s got %s", expectedID, meta.ID)
	}
	version, err := strconv.Atoi(strings.TrimSpace(meta.Version))
	if err != nil || version < 1 {
		return 0, 0, fmt.Errorf("invalid Cisco benchmark version")
	}
	release, count := 0, 0
	for _, p := range meta.Plain {
		if p.ID == "release-info" {
			count++
			m := releaseInfo.FindStringSubmatch(strings.TrimSpace(p.Text))
			if m != nil {
				release, _ = strconv.Atoi(m[1])
			}
		}
	}
	if count != 1 || release < 1 {
		return 0, 0, fmt.Errorf("invalid Cisco benchmark release metadata")
	}
	return version, release, nil
}

func selectCiscoBenchmark(root, id string) (string, []byte, error) {
	if err := privateLibraryDirectory(root); err != nil {
		return "", nil, err
	}
	var chosen string
	var content []byte
	bestV, bestR := 0, 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in Cisco library: %s", path)
		}
		if entry.IsDir() {
			return privateLibraryDirectory(path)
		}
		m := ciscoFile.FindStringSubmatch(entry.Name())
		if m == nil {
			return nil
		}
		data, err := readPrivate(path)
		if err != nil {
			return err
		}
		var meta ciscoMeta
		if err := xml.Unmarshal(data, &meta); err != nil {
			return fmt.Errorf("invalid Cisco benchmark %s: %w", path, err)
		}
		if meta.ID != id {
			return nil
		}
		v, _ := strconv.Atoi(m[1])
		r, _ := strconv.Atoi(m[2])
		if v < 1 || r < 1 {
			return fmt.Errorf("invalid Cisco version/release: %s", path)
		}
		actualV, actualR, err := validateCiscoBenchmark(data, id)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if v != actualV || r != actualR {
			return fmt.Errorf("Cisco filename/metadata version mismatch: %s", path)
		}
		if chosen == "" || v > bestV || (v == bestV && r > bestR) {
			chosen, content, bestV, bestR = path, data, v, r
		} else if v == bestV && r == bestR {
			return fmt.Errorf("ambiguous Cisco benchmark release: %s and %s", chosen, path)
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if chosen == "" {
		return "", nil, fmt.Errorf("no benchmark for exact ID %s beneath %s", id, root)
	}
	return chosen, content, nil
}

func runCisco(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("cisco-cklb", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "owner-private saved Cisco running configuration")
	benchmarkPath := flags.String("benchmark", "", "exact official Cisco manual XCCDF XML")
	libraryRoot := flags.String("library-root", "", "owner-private extracted benchmark library")
	benchmarkID := flags.String("benchmark-id", "", "exact Cisco benchmark ID, required with --library-root")
	target := flags.String("target", "", "device hostname matching config parent directory")
	dryRun := flags.Bool("dry-run", false, "validate inputs and select benchmark without writing")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	if flags.NArg() != 0 || *configPath == "" || *target == "" || !safeTarget.MatchString(*target) || strings.Contains(*target, "..") || (*benchmarkPath == "") == (*libraryRoot == "") || (*libraryRoot != "" && !ciscoID.MatchString(*benchmarkID)) || (*benchmarkPath != "" && *benchmarkID != "") {
		fmt.Fprintln(stderr, "usage: stig-evidence cisco-cklb --config PATH --target HOST (--benchmark XCCDF | --library-root DIR --benchmark-id Cisco_*_STIG) [--dry-run]")
		return 2
	}
	for _, path := range []*string{configPath, benchmarkPath, libraryRoot} {
		if *path != "" {
			absolute, err := filepath.Abs(*path)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			*path = absolute
		}
	}
	if filepath.Base(filepath.Dir(*configPath)) != *target || !strings.HasSuffix(*configPath, ".running-config") {
		fmt.Fprintln(stderr, "Cisco configuration must end in .running-config within its exact target-named directory")
		return 2
	}
	if err := privateLibraryDirectory(filepath.Dir(*configPath)); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	config, err := readPrivate(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(config) == 0 || len(config) > 8<<20 || !utf8.Valid(config) || bytes.IndexByte(config, 0) >= 0 {
		fmt.Fprintln(stderr, "Cisco configuration must be nonempty UTF-8 text without NUL and at most 8 MiB")
		return 2
	}
	var benchmark []byte
	if *libraryRoot != "" {
		*benchmarkPath, benchmark, err = selectCiscoBenchmark(*libraryRoot, *benchmarkID)
	} else {
		benchmark, err = readPrivate(*benchmarkPath)
		if err == nil {
			m := ciscoFile.FindStringSubmatch(filepath.Base(*benchmarkPath))
			if m == nil {
				err = fmt.Errorf("expected Cisco manual XCCDF filename")
			} else {
				var meta ciscoMeta
				if xmlErr := xml.Unmarshal(benchmark, &meta); xmlErr != nil {
					err = xmlErr
				} else {
					v, r, validationErr := validateCiscoBenchmark(benchmark, meta.ID)
					filenameV, _ := strconv.Atoi(m[1])
					filenameR, _ := strconv.Atoi(m[2])
					if validationErr != nil {
						err = validationErr
					} else if v != filenameV || r != filenameR {
						err = fmt.Errorf("Cisco filename/metadata version mismatch")
					} else {
						*benchmarkID = meta.ID
					}
				}
			}
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "Cisco benchmark: %v\n", err)
		return 2
	}
	fmt.Fprintf(out, "BENCHMARK %s: %s (sha256 %s)\n", *benchmarkID, *benchmarkPath, sha256Hex(benchmark))
	doc, err := draft.BuildCiscoConfig(config, *target, benchmark)
	if err != nil {
		fmt.Fprintf(stderr, "Cisco checklist: %v\n", err)
		return 2
	}
	if *dryRun {
		fmt.Fprintf(out, "CONFIG %s (sha256 %s); %d controls; no files written\n", *configPath, sha256Hex(config), len(doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)))
		return 0
	}
	counts := map[string]int{}
	automated := []map[string]string{}
	for _, item := range doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any) {
		row := item.(map[string]any)
		status := row["status"].(string)
		counts[status]++
		if status != "not_reviewed" {
			automated = append(automated, map[string]string{"group_id": row["group_id"].(string), "rule_id": row["rule_id"].(string), "status": status})
		}
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	body = append(body, '\n')
	digest := bundleDigest([]byte(draft.CiscoConfigEvaluatorVersion), config, benchmark, []byte(*target))
	prefix := strings.TrimSuffix(filepath.Base(*configPath), ".running-config")
	path := filepath.Join(filepath.Dir(*configPath), prefix+"-cisco-"+sha256Hex(benchmark)[:16]+"-"+digest[:16]+"-ASSESSMENT.cklb")
	sidecar, err := json.MarshalIndent(map[string]any{
		"schema_version": 2, "checklist_sha256": sha256Hex(body),
		"mapping_method":    "config-only pinned automatic rules; unsupported controls require human review",
		"evaluator_version": draft.CiscoConfigEvaluatorVersion, "status_counts": counts, "automated_controls": automated,
		"config": evidenceInput{*configPath, sha256Hex(config)}, "benchmark": evidenceInput{*benchmarkPath, sha256Hex(benchmark)}, "target": *target, "benchmark_id": *benchmarkID,
	}, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	sidecar = append(sidecar, '\n')
	skipped, err := writeBatchResult(path, body)
	if err != nil {
		fmt.Fprintf(stderr, "Cisco checklist: %v\n", err)
		return 2
	}
	_, err = writeBatchResult(path+".provenance.json", sidecar)
	if err != nil {
		fmt.Fprintf(stderr, "Cisco provenance: %v (checklist retained for safe retry)\n", err)
		return 2
	}
	if skipped {
		fmt.Fprintf(out, "SKIP %s (identical checklist and provenance)\n", path)
	} else {
		fmt.Fprintf(out, "CREATED %s (config-based automatic verdicts; unassessed controls require human review)\n", path)
	}
	return 0
}
