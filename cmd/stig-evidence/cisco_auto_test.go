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

func TestCiscoCLIEmitsAutomaticVerdictWithoutOverwritingPriorCandidate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	host := filepath.Join(root, "DOD-ACC-SW01")
	if err := os.MkdirAll(host, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(host, "scan.running-config")
	config := []byte("hostname DOD-ACC-SW01\nspanning-tree loopguard default\nusername fake secret 9 SENSITIVE_TEST_MARKER\n")
	if err := os.WriteFile(cfg, config, 0600); err != nil {
		t.Fatal(err)
	}
	bench := filepath.Join(root, "U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml")
	xml := []byte(`<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Cisco_IOS_XE_Switch_L2S_STIG"><title>IOS-XE Switch L2S</title><version>3</version><plain-text id="release-info">Release: 2 Benchmark Date: 30 Sep 2026</plain-text><Group id="V-220657"><Rule id="SV-220657r856279_rule" severity="medium"><title>The Cisco switch must have STP Loop Guard enabled.</title><version>CISC-L2-000110</version><check><check-content>Review the switch configuration for spanning-tree loopguard default. If STP Loop Guard is not enabled, this is a finding.</check-content></check></Rule></Group><Group id="V-220666"><Rule id="SV-220666r539671_rule" severity="medium"><title>The Cisco switch must have all trunk links enabled statically.</title><version>CISC-L2-000200</version><check><check-content>Review show interfaces switchport; if trunk negotiation is enabled this is a finding.</check-content></check></Rule></Group></Benchmark>`)
	if err := os.WriteFile(bench, xml, 0600); err != nil {
		t.Fatal(err)
	}
	prior := filepath.Join(host, "scan-cisco-"+sha256Hex(xml)[:16]+"-"+bundleDigest([]byte("cisco-config-review-v1"), config, xml, []byte("DOD-ACC-SW01"))[:16]+"-ASSESSMENT.cklb")
	if err := os.WriteFile(prior, []byte("PRIOR CANDIDATE MUST REMAIN"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"cisco-cklb", "--config", cfg, "--target", "DOD-ACC-SW01", "--benchmark", bench}
	var out, errs bytes.Buffer
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if body, _ := os.ReadFile(prior); string(body) != "PRIOR CANDIDATE MUST REMAIN" {
		t.Fatal("overwrote prior candidate")
	}
	paths, _ := filepath.Glob(filepath.Join(host, "*.cklb"))
	if len(paths) != 2 {
		t.Fatalf("wanted prior and new, got %v", paths)
	}
	var path string
	for _, p := range paths {
		if p != prior {
			path = p
		}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	rows := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)
	if rows[0].(map[string]any)["status"] != "not_a_finding" || rows[1].(map[string]any)["status"] != "not_reviewed" {
		t.Fatalf("wrong auto statuses: %+v", rows)
	}
	var sidecar map[string]any
	raw, err := os.ReadFile(path + ".provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &sidecar); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if sidecar["checklist_sha256"] != hex.EncodeToString(sum[:]) || sidecar["evaluator_version"] != "cisco-config-auto-v4" {
		t.Fatalf("unbound auto output: %+v", sidecar)
	}
	if controls, ok := sidecar["automated_controls"].([]any); !ok || len(controls) != 1 {
		t.Fatalf("missing decision inventory: %+v", sidecar)
	}
	if !strings.Contains(doc["title"].(string), "AUTO") || bytes.Contains(append(body, raw...), []byte("SENSITIVE_TEST_MARKER")) {
		t.Fatal("missing auto label or secret leaked")
	}
	for _, p := range []string{path, path + ".provenance.json"} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("insecure artifact %s: %v", p, err)
		}
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), "SKIP") {
		t.Fatalf("rerun %d %q %q", code, out.String(), errs.String())
	}
}
