package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func xccdfFixture(t *testing.T, config string) (string, string, string, string) {
	t.Helper()
	root := t.TempDir()
	host := filepath.Join(root, "sw1")
	lib := filepath.Join(root, "lib")
	scanDir := filepath.Join(root, "scans", "sw1")
	checkDir := filepath.Join(root, "checklists", "Cisco_IOS_Router_NDM_STIG", "sw1")
	for _, dir := range []string{host, lib, scanDir, checkDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(host, "scan.running-config")
	bench := filepath.Join(lib, "U_Cisco_IOS_Router_NDM_STIG_V3R9_Manual-xccdf.xml")
	results := filepath.Join(scanDir, "sw1.Cisco_IOS_Router_NDM_STIG.results.xml")
	checklist := filepath.Join(checkDir, "sw1.cklb")
	if err := os.WriteFile(cfg, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bench, []byte(ciscoBenchmark), 0600); err != nil {
		t.Fatal(err)
	}
	return cfg, bench, results, checklist
}

func xccdfScanArgs(cfg, bench, results string) []string {
	return []string{"cisco-xccdf", "--config", cfg, "--benchmark", bench, "--target", "sw1",
		"--fqdn", "sw1.example.test", "--ip", "192.0.2.10", "--mac", "02:00:00:00:00:10",
		"--role", "Access switch", "--target-type", "Cisco IOS switch", "--out", results}
}

func TestCiscoXCCDFRejectsHostnameThatDoesNotMatchTarget(t *testing.T) {
	cfg, bench, results, _ := xccdfFixture(t, "hostname other\nversion 15.2\nend\n")
	var out, errs bytes.Buffer
	if code := run(xccdfScanArgs(cfg, bench, results), &out, &errs); code == 0 || !strings.Contains(errs.String(), `hostname command is "other"`) {
		t.Fatalf("exit %d stderr %s", code, errs.String())
	}
}

func TestCiscoXCCDFRejectsConflictingHostname(t *testing.T) {
	cfg, bench, results, _ := xccdfFixture(t, "hostname sw1\nhostname other\nversion 15.2\nend\n")
	var out, errs bytes.Buffer
	if code := run(xccdfScanArgs(cfg, bench, results), &out, &errs); code == 0 || !strings.Contains(errs.String(), "conflicting hostname") {
		t.Fatalf("exit %d stderr %s", code, errs.String())
	}
}

func TestCiscoXCCDFConversionBindsProvenanceAndCompleteness(t *testing.T) {
	cfg, bench, results, checklist := xccdfFixture(t, "hostname sw1\nversion 15.2\nend\n")
	var out, errs bytes.Buffer
	if code := run(xccdfScanArgs(cfg, bench, results), &out, &errs); code != 0 {
		t.Fatalf("scan exit %d: %s", code, errs.String())
	}
	out.Reset()
	errs.Reset()
	if code := run([]string{"xccdf-cklb", "--results", results, "--benchmark", bench, "--out", checklist}, &out, &errs); code != 0 {
		t.Fatalf("convert exit %d: %s", code, errs.String())
	}
	body, err := os.ReadFile(checklist)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	target := doc["target_data"].(map[string]any)
	if target["host_name"] != "sw1" || target["fqdn"] != "sw1.example.test" || target["ip_address"] != "192.0.2.10" || target["mac_address"] != "02:00:00:00:00:10" {
		t.Fatalf("target data: %#v", target)
	}
	sum := sha256.Sum256(body)
	sidecar, err := os.ReadFile(checklist + ".provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sidecar, []byte(hex.EncodeToString(sum[:]))) || !bytes.Contains(sidecar, []byte(`"config_complete": true`)) || !bytes.Contains(sidecar, []byte("network XCCDF result copied")) {
		t.Fatalf("unbound provenance: %s", sidecar)
	}
	page, err := os.ReadFile(strings.TrimSuffix(checklist, ".cklb") + ".review.html")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(page, []byte("Snapshot is incomplete")) || !bytes.Contains(page, []byte("sw1.example.test")) {
		t.Fatalf("review page completeness or identity: %s", page[:min(400, len(page))])
	}
	for _, file := range []string{checklist, checklist + ".provenance.json"} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private mode %s: %v", file, err)
		}
	}
}

func TestCiscoXCCDFIncompleteSnapshotStaysVisible(t *testing.T) {
	cfg, bench, results, checklist := xccdfFixture(t, "hostname sw1\n")
	var out, errs bytes.Buffer
	if code := run(xccdfScanArgs(cfg, bench, results), &out, &errs); code != 0 {
		t.Fatalf("scan exit %d: %s", code, errs.String())
	}
	if code := run([]string{"xccdf-cklb", "--results", results, "--benchmark", bench, "--out", checklist}, &out, &errs); code != 0 {
		t.Fatalf("convert exit %d: %s", code, errs.String())
	}
	page, err := os.ReadFile(strings.TrimSuffix(checklist, ".cklb") + ".review.html")
	if err != nil || !bytes.Contains(page, []byte("Snapshot is incomplete")) {
		t.Fatalf("incomplete snapshot was presented as complete: %v", err)
	}
	sidecar, err := os.ReadFile(checklist + ".provenance.json")
	if err != nil || !bytes.Contains(sidecar, []byte(`"config_complete": false`)) {
		t.Fatalf("provenance completeness: %s %v", sidecar, err)
	}
}

func TestCiscoXCCDFAppliesDeviceTailoring(t *testing.T) {
	cfg, bench, results, checklist := xccdfFixture(t, "hostname sw1\nversion 15.2\nend\n")
	benchmark, err := os.ReadFile(bench)
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(filepath.Dir(cfg), "Cisco_IOS_Router_NDM_STIG.tailoring.yaml")
	_ = benchmark
	hostPolicy := "schema_version: 3\nbenchmark_id: Cisco_IOS_Router_NDM_STIG\nrules:\n  - stig_id: V-215662\n    sv_id: SV-215662r1269385_rule\n    status: not_applicable\n    comment: Site accepts this session limit.\n"
	if err := os.WriteFile(policy, []byte(hostPolicy), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := run(xccdfScanArgs(cfg, bench, results), &out, &errs); code != 0 {
		t.Fatalf("scan exit %d: %s", code, errs.String())
	}
	if code := run([]string{"xccdf-cklb", "--results", results, "--benchmark", bench, "--out", checklist}, &out, &errs); code != 0 {
		t.Fatalf("convert exit %d: %s", code, errs.String())
	}
	body, err := os.ReadFile(checklist)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["group_id"] != "V-215662" || row["status"] != "not_applicable" || !strings.Contains(row["comments"].(string), "ADMINISTRATOR OVERRIDE") {
		t.Fatalf("override was not applied: %#v", row)
	}
	policySum := sha256.Sum256([]byte(hostPolicy))
	sidecar, err := os.ReadFile(checklist + ".provenance.json")
	if err != nil || !bytes.Contains(sidecar, []byte(hex.EncodeToString(policySum[:]))) {
		t.Fatalf("tailoring hash missing: %s %v", sidecar, err)
	}
	suggestion, err := os.ReadFile(strings.TrimSuffix(checklist, ".cklb") + ".tailoring.yaml")
	if err != nil || !bytes.Contains(suggestion, []byte("status: not_applicable")) || !bytes.Contains(suggestion, []byte("Site accepts this session limit.")) {
		t.Fatalf("worksheet dropped the applied override: %s %v", suggestion, err)
	}
}
