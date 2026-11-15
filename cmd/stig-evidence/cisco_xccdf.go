package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/zcook44/burden-of-proof/internal/ciscoconfig"
	"github.com/zcook44/burden-of-proof/internal/draft"
	"github.com/zcook44/burden-of-proof/internal/netxccdf"
)

func runCiscoXCCDF(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("cisco-xccdf", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "owner-private saved Cisco running configuration")
	benchmarkPath := flags.String("benchmark", "", "exact official Cisco manual XCCDF XML")
	libraryRoot := flags.String("library-root", "", "owner-private extracted benchmark library")
	benchmarkID := flags.String("benchmark-id", "", "exact Cisco benchmark ID")
	target := flags.String("target", "", "device hostname")
	fqdn := flags.String("fqdn", "", "device FQDN, beginning with the hostname")
	ipAddress := flags.String("ip", "", "management IP address")
	macAddress := flags.String("mac", "", "management MAC address")
	role := flags.String("role", "", "device role recorded on the checklist")
	targetType := flags.String("target-type", "", "checklist target type")
	technology := flags.String("technology", "Network", "checklist technology area")
	portRoles := flags.String("port-roles", "", "optional owner-private interface role CSV")
	outPath := flags.String("out", "", "private XCCDF results path named for the device")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	identity := netxccdf.Identity{HostName: *target, FQDN: *fqdn, IPAddress: *ipAddress, MACAddress: *macAddress, Role: *role, TargetType: *targetType, TechnologyArea: *technology}
	if err := identity.Normalize(); err != nil {
		fmt.Fprintf(stderr, "cisco-xccdf: %v\n", err)
		return 2
	}
	if flags.NArg() != 0 || *configPath == "" || *outPath == "" || (*benchmarkPath == "") == (*libraryRoot == "") || (*libraryRoot != "" && !ciscoID.MatchString(*benchmarkID)) {
		fmt.Fprintln(stderr, "usage: stig-evidence cisco-xccdf --config PATH --target HOST --fqdn FQDN --ip ADDR --mac ADDR --role ROLE --target-type TYPE (--benchmark XCCDF | --library-root DIR --benchmark-id Cisco_*_STIG) --out HOST.BENCHMARK.results.xml [--technology AREA] [--port-roles CSV]")
		return 2
	}
	for _, path := range []*string{configPath, benchmarkPath, libraryRoot, portRoles, outPath} {
		if *path == "" {
			continue
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		*path = absolute
	}
	if !strings.HasSuffix(*configPath, ".running-config") || filepath.Base(filepath.Dir(*configPath)) != identity.HostName {
		fmt.Fprintln(stderr, "Cisco configuration must end in .running-config within its exact target-named directory")
		return 2
	}
	config, benchmark, resolvedBenchmark, id, roles, err := loadCiscoScanInputs(*configPath, *benchmarkPath, *libraryRoot, *benchmarkID, *portRoles)
	if err != nil {
		fmt.Fprintf(stderr, "cisco-xccdf: %v\n", err)
		return 2
	}
	parsed, err := ciscoconfig.Parse(config)
	if err != nil {
		fmt.Fprintf(stderr, "cisco-xccdf: %v\n", err)
		return 2
	}
	if parsed.Uncertain && strings.Contains(parsed.Uncertainty, "hostname") {
		fmt.Fprintf(stderr, "cisco-xccdf: %s\n", parsed.Uncertainty)
		return 2
	}
	if parsed.Hostname != identity.HostName {
		fmt.Fprintf(stderr, "cisco-xccdf: %s hostname command is %q\n", identity.HostName, parsed.Hostname)
		return 2
	}
	if err := netxccdf.RequireResultsPath(*outPath, identity.HostName, id); err != nil {
		fmt.Fprintf(stderr, "cisco-xccdf: %v\n", err)
		return 2
	}
	doc, err := draft.BuildCiscoReview(config, identity.HostName, benchmark, roles)
	if err != nil {
		fmt.Fprintf(stderr, "cisco-xccdf: %v\n", err)
		return 2
	}
	policyDir := ciscoPolicyDirectory(filepath.Dir(*configPath), filepath.Dir(resolvedBenchmark), id)
	policyRules, policyPath, policyBytes, err := loadCiscoTailoring(policyDir, id, benchmark, doc)
	if err != nil {
		fmt.Fprintf(stderr, "cisco-xccdf: %v\n", err)
		return 2
	}
	tailoringSHA := ""
	if policyPath != "" {
		applyCiscoTailoring(doc, policyRules)
		tailoringSHA = sha256Hex(policyBytes)
		fmt.Fprintf(out, "TAILORING %s (sha256 %s)\n", policyPath, tailoringSHA)
	}
	body, err := netxccdf.FromChecklist(identity, id, netxccdf.ResultMeta{
		ConfigSHA256: sha256Hex(config), ConfigComplete: parsed.Complete(ciscoconfig.Family(id)), TailoringSHA256: tailoringSHA,
	}, doc, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "cisco-xccdf: %v\n", err)
		return 2
	}
	if err := ensurePrivateDir(filepath.Dir(*outPath)); err != nil {
		fmt.Fprintf(stderr, "cisco-xccdf: %v\n", err)
		return 2
	}
	if _, err := writeBatchResult(*outPath, body); err != nil {
		fmt.Fprintf(stderr, "cisco-xccdf: %v\n", err)
		return 2
	}
	fmt.Fprintf(out, "XCCDF %s (%s, %d rule-results)\n", *outPath, id, len(doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)))
	return 0
}

func runXCCDFCKLB(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("xccdf-cklb", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resultsPath := flags.String("results", "", "owner-private network XCCDF results")
	benchmarkPath := flags.String("benchmark", "", "exact official Cisco manual XCCDF XML")
	libraryRoot := flags.String("library-root", "", "owner-private extracted benchmark library")
	outPath := flags.String("out", "", "new private CKLB path")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	if flags.NArg() != 0 || *resultsPath == "" || *outPath == "" || !strings.HasSuffix(*outPath, ".cklb") || (*benchmarkPath == "") == (*libraryRoot == "") {
		fmt.Fprintln(stderr, "usage: stig-evidence xccdf-cklb --results HOST/HOST.BENCHMARK.results.xml (--benchmark XCCDF | --library-root DIR) --out HOST/HOST.cklb")
		return 2
	}
	for _, path := range []*string{resultsPath, benchmarkPath, libraryRoot, outPath} {
		if *path == "" {
			continue
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		*path = absolute
	}
	raw, err := readPrivate(*resultsPath)
	if err != nil {
		fmt.Fprintf(stderr, "xccdf-cklb: %v\n", err)
		return 2
	}
	scan, err := netxccdf.Parse(raw)
	if err != nil {
		fmt.Fprintf(stderr, "xccdf-cklb: %v\n", err)
		return 2
	}
	if err := netxccdf.RequireResultsPath(*resultsPath, scan.Host, scan.BenchmarkID); err != nil {
		fmt.Fprintf(stderr, "xccdf-cklb: %v\n", err)
		return 2
	}
	if err := netxccdf.RequireChecklistPath(*outPath, scan.Host); err != nil {
		fmt.Fprintf(stderr, "xccdf-cklb: %v\n", err)
		return 2
	}
	var benchmark []byte
	if *libraryRoot != "" {
		*benchmarkPath, benchmark, err = selectCiscoBenchmark(*libraryRoot, scan.BenchmarkID)
	} else {
		benchmark, err = readPrivate(*benchmarkPath)
	}
	if err != nil {
		fmt.Fprintf(stderr, "xccdf-cklb: %v\n", err)
		return 2
	}
	doc, err := draft.BuildFromNetworkScan(benchmark, scan)
	if err != nil {
		fmt.Fprintf(stderr, "xccdf-cklb: %v\n", err)
		return 2
	}
	if err := writeReviewBundle(*outPath, doc, *benchmarkPath, benchmark, *resultsPath, raw, scan); err != nil {
		fmt.Fprintf(stderr, "xccdf-cklb: %v\n", err)
		return 2
	}
	fmt.Fprintf(out, "CKLB %s from %s (%s)\n", *outPath, *resultsPath, scan.BenchmarkID)
	return 0
}

func loadCiscoScanInputs(configPath, benchmarkPath, libraryRoot, benchmarkID, portRoles string) ([]byte, []byte, string, string, ciscoconfig.RoleTable, error) {
	if err := privateLibraryDirectory(filepath.Dir(configPath)); err != nil {
		return nil, nil, "", "", ciscoconfig.RoleTable{}, err
	}
	config, err := readPrivate(configPath)
	if err != nil {
		return nil, nil, "", "", ciscoconfig.RoleTable{}, err
	}
	if len(config) == 0 || len(config) > 8<<20 || !utf8Valid(config) {
		return nil, nil, "", "", ciscoconfig.RoleTable{}, fmt.Errorf("configuration must be nonempty UTF-8 text at most 8 MiB")
	}
	var benchmark []byte
	if libraryRoot != "" {
		benchmarkPath, benchmark, err = selectCiscoBenchmark(libraryRoot, benchmarkID)
	} else {
		benchmark, err = readPrivate(benchmarkPath)
		if err == nil {
			var meta ciscoMeta
			if xmlErr := xml.Unmarshal(benchmark, &meta); xmlErr != nil {
				err = xmlErr
			} else {
				benchmarkID = meta.ID
			}
		}
	}
	if err != nil {
		return nil, nil, "", "", ciscoconfig.RoleTable{}, err
	}
	roles, _, err := readPortRoles(portRoles)
	if err != nil {
		return nil, nil, "", "", ciscoconfig.RoleTable{}, err
	}
	return config, benchmark, benchmarkPath, benchmarkID, roles, nil
}

func writeReviewBundle(outPath string, doc map[string]any, benchmarkPath string, benchmark []byte, resultsPath string, results []byte, scan netxccdf.Scan) error {
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := ensurePrivateDir(filepath.Dir(outPath)); err != nil {
		return err
	}
	if _, err := writeBatchResult(outPath, body); err != nil {
		return err
	}
	counts := map[string]int{}
	for _, item := range doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any) {
		counts[item.(map[string]any)["status"].(string)]++
	}
	record := map[string]any{
		"schema_version": 4, "checklist_sha256": sha256Hex(body),
		"mapping_method":    "network XCCDF result copied onto the official Cisco benchmark; the configuration was not scored again",
		"evaluator_version": draft.CiscoConfigEvaluatorVersion, "status_counts": counts,
		"results": evidenceInput{resultsPath, sha256Hex(results)}, "benchmark": evidenceInput{benchmarkPath, sha256Hex(benchmark)},
		"running_config_sha256": scan.ConfigSHA256, "config_complete": scan.ConfigComplete,
		"target": scan.Host, "fqdn": scan.Identity.FQDN, "ip_address": scan.Identity.IPAddress, "mac_address": scan.Identity.MACAddress,
		"benchmark_id": scan.BenchmarkID,
	}
	if scan.TailoringSHA256 != "" {
		record["tailoring_sha256"] = scan.TailoringSHA256
	}
	sidecar, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if _, err := writeBatchResult(outPath+".provenance.json", append(sidecar, '\n')); err != nil {
		return fmt.Errorf("provenance: %w (checklist retained for safe retry)", err)
	}
	tailorName := strings.TrimSuffix(filepath.Base(outPath), ".cklb") + ".tailoring.yaml"
	page, err := reviewHTML(doc["target_data"].(map[string]any)["host_name"].(string), scan.BenchmarkID, scan.ConfigComplete, tailorName, doc)
	if err != nil {
		return err
	}
	if _, err := writeBatchResult(strings.TrimSuffix(outPath, ".cklb")+".review.html", page); err != nil {
		return err
	}
	suggestion, err := suggestCiscoTailoring(scan.BenchmarkID, benchmark, doc)
	if err != nil {
		return err
	}
	_, err = writeBatchResult(strings.TrimSuffix(outPath, ".cklb")+".tailoring.yaml", suggestion)
	return err
}
