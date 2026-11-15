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

const ciscoBenchmark = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Cisco_IOS_Router_NDM_STIG"><title>Cisco IOS Router NDM STIG</title><version>3</version><plain-text id="release-info">Release: 9 Benchmark Date: 30 Sep 2026</plain-text><Group id="V-215662"><title>Management sessions</title><Rule id="SV-215662r1269385_rule" severity="high" weight="10.0"><title>Limit sessions</title><version>CISC-ND-001</version><fixtext>Review device configuration.</fixtext></Rule></Group><Group id="V-215667"><Rule id="SV-215667r1137875_rule" severity="medium"/></Group></Benchmark>`

func ciscoFixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private")
	host := filepath.Join(root, "router1.example.test")
	lib := filepath.Join(root, "lib")
	for _, dir := range []string{root, host, lib} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(host, "scan.running-config")
	bench := filepath.Join(lib, "U_Cisco_IOS_Router_NDM_STIG_V3R9_Manual-xccdf.xml")
	if err := os.WriteFile(cfg, []byte("hostname router1\nline vty 0 4\n transport input ssh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bench, []byte(ciscoBenchmark), 0600); err != nil {
		t.Fatal(err)
	}
	return root, host, cfg, bench
}

func TestCiscoCLIExplicitBenchmarkCreatesPrivateReviewCandidate(t *testing.T) {
	_, host, cfg, bench := ciscoFixture(t)
	var out, errs bytes.Buffer
	args := []string{"cisco-cklb", "--config", cfg, "--benchmark", bench, "--target", "router1.example.test"}
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	outputs, err := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if err != nil || len(outputs) != 1 {
		t.Fatalf("outputs %v: %v", outputs, err)
	}
	body, err := os.ReadFile(outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	stig := doc["stigs"].([]any)[0].(map[string]any)
	if stig["stig_id"] != "Cisco_IOS_Router_NDM_STIG" {
		t.Fatalf("wrong benchmark: %v", stig["stig_id"])
	}
	rows := stig["rules"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows=%d", len(rows))
	}
	for _, r := range rows {
		row := r.(map[string]any)
		if row["status"] != "not_reviewed" || !strings.Contains(row["finding_details"].(string), "SHA-256") || !strings.Contains(row["comments"].(string), "NOT REVIEWED") {
			t.Fatalf("unsafe candidate: %+v", row)
		}
	}
	sum := sha256.Sum256(body)
	sidecar, err := os.ReadFile(outputs[0] + ".provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sidecar, []byte(hex.EncodeToString(sum[:]))) || !bytes.Contains(sidecar, []byte("config-only")) {
		t.Fatalf("unbound provenance: %s", sidecar)
	}
	for _, file := range []string{outputs[0], outputs[0] + ".provenance.json"} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe output %s: %v %v", file, info, err)
		}
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), "SKIP") {
		t.Fatalf("rerun %d %q %q", code, out.String(), errs.String())
	}
}

func TestCiscoCLILibrarySelectionRequiresExactBenchmarkID(t *testing.T) {
	_, host, cfg, bench := ciscoFixture(t)
	var out, errs bytes.Buffer
	args := []string{"cisco-cklb", "--config", cfg, "--library-root", filepath.Dir(bench), "--benchmark-id", "Cisco_IOS_Router_NDM_STIG", "--target", "router1.example.test", "--dry-run"}
	if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), "Cisco_IOS_Router_NDM_STIG") {
		t.Fatalf("selection %d %q %q", code, out.String(), errs.String())
	}
	matches, _ := filepath.Glob(filepath.Join(host, "*.cklb"))
	if len(matches) != 0 {
		t.Fatal("dry-run wrote CKLB")
	}
	out.Reset()
	errs.Reset()
	bad := append([]string{}, args...)
	bad[6] = "Cisco_IOS_Router_RTR_STIG"
	if code := run(bad, &out, &errs); code == 0 {
		t.Fatal("accepted wrong benchmark ID")
	}
}

func TestCiscoCLIRejectsUnsafeInputAndAmbiguousBenchmarkWithoutOutput(t *testing.T) {
	_, host, cfg, bench := ciscoFixture(t)
	link := filepath.Join(host, "linked.running-config")
	if err := os.Symlink(cfg, link); err != nil {
		t.Fatal(err)
	}
	for _, arg := range [][]string{
		{"cisco-cklb", "--config", link, "--benchmark", bench, "--target", "router1.example.test"},
		{"cisco-cklb", "--config", cfg, "--benchmark", bench, "--target", "other.example.test"},
	} {
		var out, errs bytes.Buffer
		if code := run(arg, &out, &errs); code == 0 {
			t.Fatalf("unsafe input accepted: %v", arg)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(host, "*.cklb"))
	if len(matches) != 0 {
		t.Fatal("rejected input wrote CKLB")
	}
}

func TestCiscoCLISelectsActualCiscoFilenameVariantsByXMLIdentity(t *testing.T) {
	_, _, cfg, original := ciscoFixture(t)
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ file, id string }{
		{"U_Cisco_ACI_L2S_V1R2_STIG_Manual-xccdf.xml", "Cisco_ACI_L2S_STIG"},
		{"U_Cisco_IOS-XE_Switch_NDM_STIG_V3R6_Manual-xccdf.xml", "Cisco_IOS_XE_Switch_NDM_STIG"},
		{"U_Cisco_ACI_RTR_Manual_V1R2_STIG_Manual-xccdf.xml", "Cisco_ACI_RTR_STIG"},
		{"U_Cisco_ASA_Firewall_STIG_V2R1_Manual-xccdf.xml", "Cisco_ASA_FW_STIG"},
	} {
		version, release := "1", "2"
		if strings.Contains(tc.file, "V3R6") {
			version, release = "3", "6"
		}
		if strings.Contains(tc.file, "V2R1") {
			version, release = "2", "1"
		}
		xml := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="` + tc.id + `"><title>Test</title><version>` + version + `</version><plain-text id="release-info">Release: ` + release + ` Benchmark Date: 30 Sep 2026</plain-text><Group id="V-123"><Rule id="SV-123r456_rule" severity="high"/></Group></Benchmark>`
		path := filepath.Join(filepath.Dir(original), tc.file)
		if err := os.WriteFile(path, []byte(xml), 0600); err != nil {
			t.Fatal(err)
		}
		var out, errs bytes.Buffer
		args := []string{"cisco-cklb", "--config", cfg, "--target", "router1.example.test", "--library-root", filepath.Dir(original), "--benchmark-id", tc.id, "--dry-run"}
		if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), tc.file) {
			t.Fatalf("%s: exit=%d, out=%s err=%s", tc.file, code, out.String(), errs.String())
		}
	}
}
