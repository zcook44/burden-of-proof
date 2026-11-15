package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sourceFixture(major int) string {
	return fmt.Sprintf(`<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL-%d"><Group id="g"><Rule id="ssg_a"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-100</reference></Rule></Group><TestResult><target>node%d.example.test</target><profile idref="xccdf_org.ssgproject.content_profile_stig"/><rule-result idref="ssg_a"><result>pass</result></rule-result></TestResult></Benchmark>`, major, major)
}
func officialFixture(major, release int) string {
	return fmt.Sprintf(`<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_%d_STIG"><title>RHEL %d STIG</title><version>1</version><plain-text id="release-info">Release: %d Benchmark Date: 30 Sep 2026</plain-text><Group id="V-100"><Rule id="SV-100r1_rule" severity="high"/></Group></Benchmark>`, major, major, release)
}

const htmlFixture = `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">pass</span><div class="check-system-details"><div class="panel-body"><h4><span class="label-primary">verify setting</span><span class="label-default">oval:test:tst:1</span></h4><table><thead><tr><th>Result of item-state comparison</th><th>Value</th></tr></thead><tbody><tr><td>true</td><td>enabled</td></tr></tbody></table></div></div></div>`

func TestBatchMixedRHELTreeChoosesNewestPerScan(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inventory")
	library := filepath.Join(t.TempDir(), "library")
	for _, dir := range []string{root, library} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, major := range []int{7, 8, 9, 10} {
		host := filepath.Join(root, fmt.Sprintf("node%d.example.test", major))
		if err := os.Mkdir(host, 0700); err != nil {
			t.Fatal(err)
		}
		privateBench(t, host, "run.results.xml", sourceFixture(major))
		privateBench(t, host, "run.report.html", htmlFixture)
		privateBench(t, library, fmt.Sprintf("U_RHEL_%d_STIG_V1R1_Manual-xccdf.xml", major), officialFixture(major, 1))
		privateBench(t, library, fmt.Sprintf("U_RHEL_%d_STIG_V1R2_Manual-xccdf.xml", major), officialFixture(major, 2))
	}
	var out, errs bytes.Buffer
	args := []string{"batch-cklb", "--input-root", root, "--library-root", library}
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("batch failed %d: %s", code, errs.String())
	}
	if !strings.Contains(out.String(), "complete: 4 bundles; created=4 skipped=0") {
		t.Fatalf("incomplete: %s", out.String())
	}
	for _, major := range []int{7, 8, 9, 10} {
		files, err := filepath.Glob(filepath.Join(root, fmt.Sprintf("node%d.example.test", major), "*-ASSESSMENT.cklb"))
		if err != nil || len(files) != 1 {
			t.Fatalf("RHEL %d files: %v %v", major, files, err)
		}
		b, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		stig := doc["stigs"].([]any)[0].(map[string]any)
		row := stig["rules"].([]any)[0].(map[string]any)
		if stig["stig_id"] != fmt.Sprintf("RHEL_%d_STIG", major) || row["status"] != "not_a_finding" || row["rule_id_src"] != "SV-100r1_rule" {
			t.Fatalf("RHEL %d mismatch: %v %v", major, stig["stig_id"], row)
		}
		if _, err := os.Stat(files[0] + ".provenance.json"); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), "created=0 skipped=4") {
		t.Fatalf("rerun %d %s %s", code, out.String(), errs.String())
	}
}

func TestLibrarySelectsMatchingFamilyAndRejectsMismatchedMetadata(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	for _, major := range []int{7, 8, 9, 10} {
		privateBench(t, root, fmt.Sprintf("U_RHEL_%d_STIG_V1R1_Manual-xccdf.xml", major), officialFixture(major, 1))
	}
	for _, major := range []int{7, 8, 9, 10} {
		path, _, err := latestBenchmark(root, []byte(sourceFixture(major)))
		if err != nil || !strings.Contains(path, fmt.Sprintf("U_RHEL_%d_STIG", major)) {
			t.Fatalf("RHEL %d path=%s err=%v", major, path, err)
		}
	}
	privateBench(t, root, "U_RHEL_8_STIG_V1R2_Manual-xccdf.xml", officialFixture(7, 2))
	if _, _, err := latestBenchmark(root, []byte(sourceFixture(8))); err == nil {
		t.Fatal("wrong-family metadata accepted")
	}
}

func TestBatchXCCDFOnlyKeepsAbsentEvidenceExplicit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inventory")
	host := filepath.Join(root, "node8.example.test")
	library := filepath.Join(t.TempDir(), "library")
	for _, dir := range []string{root, host, library} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	privateBench(t, host, "run.results.xml", sourceFixture(8))
	privateBench(t, library, "U_RHEL_8_STIG_V1R1_Manual-xccdf.xml", officialFixture(8, 1))
	var out, errs bytes.Buffer
	if code := run([]string{"batch-cklb", "--input-root", root, "--library-root", library}, &out, &errs); code != 0 {
		t.Fatalf("XCCDF-only conversion failed %d: %s", code, errs.String())
	}
	files, _ := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if len(files) != 1 {
		t.Fatalf("missing checklist: %v", files)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["status"] != "not_a_finding" || !strings.Contains(row["finding_details"].(string), "No HTML or ARF host observation") {
		t.Fatalf("unlabeled XML-only evidence: %v", row)
	}
	sidecar, err := os.ReadFile(files[0] + ".provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var prov map[string]any
	if err := json.Unmarshal(sidecar, &prov); err != nil {
		t.Fatal(err)
	}
	if _, ok := prov["html"]; ok {
		t.Fatalf("invented HTML evidence: %v", prov["html"])
	}
}
