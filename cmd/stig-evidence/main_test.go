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

func TestReconcileCLIEmitsPrivateNoOverwriteReport(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	scan := filepath.Join(dir, "scan.xml")
	benchmark := filepath.Join(dir, "official.xml")
	out := filepath.Join(dir, "report.json")
	s := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL-9"><Group id="g"><Rule id="ssg_a"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-100</reference></Rule></Group><TestResult><target>node.example.test</target><profile idref="xccdf_org.ssgproject.content_profile_stig"/><rule-result idref="ssg_a"><result>pass</result></rule-result></TestResult></Benchmark>`
	d := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG"><title>RHEL 9 STIG</title><version>2</version><Group id="V-100"><Rule id="SV-100r2_rule" severity="high"/></Group></Benchmark>`
	if err := os.WriteFile(scan, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(benchmark, []byte(d), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"reconcile", "--scan", scan, "--benchmark", benchmark, "--out", out}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("output mode %v", info.Mode())
	}
	var report struct {
		Controls []struct {
			GroupID string `json:"disa_group_id"`
			RuleID  string `json:"disa_rule_id"`
			Status  string `json:"candidate_status"`
		} `json:"controls"`
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Controls) != 1 || report.Controls[0].GroupID != "V-100" || report.Controls[0].RuleID != "SV-100r2_rule" || report.Controls[0].Status != "not_a_finding" {
		t.Fatalf("bad report: %+v", report)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(args, &stdout, &stderr); code == 0 {
		t.Fatal("existing report overwritten")
	}
	draftPath := filepath.Join(dir, "draft.cklb")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"draft-cklb", "--scan", scan, "--benchmark", benchmark, "--out", draftPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("draft exit %d: %s", code, stderr.String())
	}
	contents, err := os.ReadFile(draftPath)
	if err != nil {
		t.Fatal(err)
	}
	var draftDoc map[string]any
	if err := json.Unmarshal(contents, &draftDoc); err != nil {
		t.Fatal(err)
	}
	stigs := draftDoc["stigs"].([]any)
	rules := stigs[0].(map[string]any)["rules"].([]any)
	if rules[0].(map[string]any)["status"] != "not_a_finding" {
		t.Fatal("default numeric V/SV mapping did not set CKLB status")
	}
	info, err = os.Stat(draftPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("draft mode %v", info.Mode())
	}
	assumedPath := filepath.Join(dir, "legacy-flag.cklb")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"draft-cklb", "--assume-v-sv-equivalence", "--scan", scan, "--benchmark", benchmark, "--out", assumedPath}, &stdout, &stderr); code == 0 {
		t.Fatalf("removed flag unexpectedly accepted: %s", stderr.String())
	}
	if _, err := os.Stat(assumedPath); !os.IsNotExist(err) {
		t.Fatal("removed mapping flag wrote an output")
	}
}

func TestDraftCLIWithHTMLReportWritesCheckAndComparison(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	scan := filepath.Join(dir, "scan.xml")
	benchmark := filepath.Join(dir, "benchmark.xml")
	html := filepath.Join(dir, "report.html")
	out := filepath.Join(dir, "detail.cklb")
	s := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL-9"><Group id="g"><Rule id="ssg_a"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-100</reference></Rule></Group><TestResult><target>node.example.test</target><profile idref="xccdf_org.ssgproject.content_profile_stig"/><rule-result idref="ssg_a"><result>pass</result></rule-result></TestResult></Benchmark>`
	b := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG"><title>RHEL 9 STIG</title><version>2</version><Group id="V-100"><Rule id="SV-100r2_rule" severity="high"/></Group></Benchmark>`
	h := `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">pass</span><div class="check-system-details"><div class="panel-body"><h4><span class="label-primary">verify setting</span><span class="label-default">oval:test:tst:1</span></h4><table><thead><tr><th>Result of item-state comparison</th><th>Path</th></tr></thead><tbody><tr><td>true</td><td>/etc/settings</td></tr></tbody></table></div></div></div>`
	for path, body := range map[string]string{scan: s, benchmark: b, html: h} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"draft-cklb", "--assessment-view", "--html-report", html, "--scan", scan, "--benchmark", benchmark, "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	rule := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if !strings.Contains(rule["comments"].(string), "Path: /etc/settings") || !strings.Contains(rule["finding_details"].(string), "verify setting") {
		t.Fatal("report evidence not exported")
	}
	sidecar, err := os.ReadFile(out + ".provenance.json")
	if err != nil {
		t.Fatalf("missing single-scan provenance: %v", err)
	}
	var provenance struct {
		ChecklistSHA256 string `json:"checklist_sha256"`
		Reconciliation  struct {
			Controls []struct {
				Sources []struct {
					RuleID string `json:"ssg_rule_id"`
				} `json:"sources"`
			} `json:"controls"`
		} `json:"reconciliation"`
	}
	if err := json.Unmarshal(sidecar, &provenance); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if provenance.ChecklistSHA256 != hex.EncodeToString(digest[:]) || len(provenance.Reconciliation.Controls) != 1 || provenance.Reconciliation.Controls[0].Sources[0].RuleID != "ssg_a" {
		t.Fatalf("unbound or incomplete source provenance: %+v", provenance)
	}
}

func TestDraftCLIRejectsInvalidARFWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	scan := filepath.Join(dir, "scan.xml")
	benchmark := filepath.Join(dir, "benchmark.xml")
	html := filepath.Join(dir, "report.html")
	arf := filepath.Join(dir, "report.arf.xml")
	out := filepath.Join(dir, "detail.cklb")
	s := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL-9"><Group id="g"><Rule id="ssg_a"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-100</reference></Rule></Group><TestResult><target>node.example.test</target><profile idref="xccdf_org.ssgproject.content_profile_stig"/><rule-result idref="ssg_a"><result>pass</result></rule-result></TestResult></Benchmark>`
	b := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG"><title>RHEL 9 STIG</title><version>2</version><Group id="V-100"><Rule id="SV-100r2_rule" severity="high"/></Group></Benchmark>`
	for path, body := range map[string]string{scan: s, benchmark: b, html: `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">pass</span></div>`, arf: `<bad/>`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"draft-cklb", "--assessment-view", "--html-report", html, "--arf", arf, "--scan", scan, "--benchmark", benchmark, "--out", out}, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "ARF") {
		t.Fatalf("invalid ARF path: %d %s", code, stderr.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("invalid ARF produced checklist")
	}
}

func TestAssessmentViewRequiresHTMLAndApprovalRequiresARF(t *testing.T) {
	for _, tc := range [][]string{{"draft-cklb", "--scan", "missing", "--benchmark", "missing", "--out", "missing.cklb", "--assessment-view"}, {"draft-cklb", "--scan", "missing", "--benchmark", "missing", "--out", "missing.cklb", "--operator-approved"}, {"draft-cklb", "--scan", "missing", "--benchmark", "missing", "--html-report", "missing", "--out", "missing.cklb", "--assessment-view", "--operator-approved"}} {
		var stdout, stderr bytes.Buffer
		if code := run(tc, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "requires") {
			t.Fatalf("unsafe flag combination accepted: %v: exit %d %q", tc, code, stderr.String())
		}
	}
}

func TestBatchCLIRecursesConvertsAndSkipsOnlyMatchingOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	nested := filepath.Join(root, "region", "node.example.test")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	benchmark := filepath.Join(root, "benchmark.xml")
	prefix := filepath.Join(nested, "scan-1")
	s := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL-9"><Group id="g"><Rule id="ssg_a"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-100</reference></Rule></Group><TestResult><target>node.example.test</target><profile idref="xccdf_org.ssgproject.content_profile_stig"/><rule-result idref="ssg_a"><result>pass</result></rule-result></TestResult></Benchmark>`
	b := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG"><title>RHEL 9 STIG</title><version>2</version><Group id="V-100"><Rule id="SV-100r2_rule" severity="high"/></Group></Benchmark>`
	h := `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">pass</span><div class="check-system-details"><div class="panel-body"><h4><span class="label-primary">verify setting</span><span class="label-default">oval:test:tst:1</span></h4><table><thead><tr><th>Result of item-state comparison</th><th>Value</th></tr></thead><tbody><tr><td>true</td><td>enabled</td></tr></tbody></table></div></div></div>`
	for p, v := range map[string]string{benchmark: b, prefix + ".results.xml": s, prefix + ".report.html": h} {
		if err := os.WriteFile(p, []byte(v), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"batch-cklb", "--input-root", root, "--benchmark", benchmark}
	var out, errs bytes.Buffer
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("batch failed %d: %s", code, errs.String())
	}
	outputs, err := filepath.Glob(prefix + "*.cklb")
	if err != nil || len(outputs) != 1 {
		t.Fatalf("no one output: %v %v", outputs, err)
	}
	if !strings.HasSuffix(outputs[0], "-ASSESSMENT.cklb") {
		t.Fatalf("unexpected output naming: %s", outputs[0])
	}
	body, err := os.ReadFile(outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["status"] != "not_a_finding" || !strings.Contains(row["comments"].(string), "enabled") || strings.Contains(doc["title"].(string), "APPROVED") {
		t.Fatal("wrong batch result")
	}
	provenance, err := os.ReadFile(outputs[0] + ".provenance.json")
	if err != nil {
		t.Fatalf("missing batch provenance: %v", err)
	}
	var record struct {
		ChecklistSHA256 string `json:"checklist_sha256"`
		Scan            struct {
			SHA256 string `json:"sha256"`
		} `json:"scan"`
		Benchmark struct {
			SHA256 string `json:"sha256"`
		} `json:"benchmark"`
		HTML struct {
			SHA256 string `json:"sha256"`
		} `json:"html"`
		Reconciliation struct {
			Controls []struct {
				Reason  string `json:"reason"`
				Sources []struct {
					RuleID string `json:"ssg_rule_id"`
				} `json:"sources"`
			} `json:"controls"`
		} `json:"reconciliation"`
	}
	if err := json.Unmarshal(provenance, &record); err != nil {
		t.Fatal(err)
	}
	ck := sha256.Sum256(body)
	sh := sha256.Sum256([]byte(s))
	bh := sha256.Sum256([]byte(b))
	hh := sha256.Sum256([]byte(h))
	if record.ChecklistSHA256 != hex.EncodeToString(ck[:]) || record.Scan.SHA256 != hex.EncodeToString(sh[:]) || record.Benchmark.SHA256 != hex.EncodeToString(bh[:]) || record.HTML.SHA256 != hex.EncodeToString(hh[:]) || len(record.Reconciliation.Controls) != 1 || record.Reconciliation.Controls[0].Reason == "" || record.Reconciliation.Controls[0].Sources[0].RuleID != "ssg_a" {
		t.Fatalf("batch provenance incomplete or unbound: %+v", record)
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), "SKIP") {
		t.Fatalf("same output not safely skipped: %d %s %s", code, out.String(), errs.String())
	}
	if err := os.WriteFile(outputs[0]+".provenance.json", []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code == 0 || !strings.Contains(errs.String(), "differs") {
		t.Fatalf("tampered provenance accepted: %d %s", code, errs.String())
	}
	if err := os.WriteFile(outputs[0]+".provenance.json", provenance, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputs[0], []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code == 0 || !strings.Contains(errs.String(), "differs") {
		t.Fatalf("tampered output accepted: %d %s", code, errs.String())
	}
}

func TestBatchCLIDryRunDoesNotWrite(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	for p, content := range map[string]string{"scan.results.xml": sourceFixture(9), "scan.report.html": htmlFixture} {
		if err := os.WriteFile(filepath.Join(root, p), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b := filepath.Join(root, "bench.xml")
	if err := os.WriteFile(b, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	code := run([]string{"batch-cklb", "--input-root", root, "--benchmark", b, "--dry-run"}, &out, &errs)
	if code != 0 || !strings.Contains(out.String(), "scan.results.xml") {
		t.Fatalf("dry run failed: %d %s %s", code, out.String(), errs.String())
	}
	paths, _ := filepath.Glob(filepath.Join(root, "*.cklb"))
	if len(paths) != 0 {
		t.Fatal("dry run wrote output")
	}
}

func TestBatchCLILibraryRootUsesNewestBenchmarkAndReportsChoice(t *testing.T) {
	root := filepath.Join(t.TempDir(), "scans")
	host := filepath.Join(root, "node.example.test")
	library := filepath.Join(t.TempDir(), "extracted-library")
	for _, dir := range []string{root, host, library} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	scan := strings.Replace(sourceRHEL9, "</TestResult>", `<profile idref="xccdf_org.ssgproject.content_profile_stig"/><rule-result idref="ssg_a"><result>pass</result></rule-result></TestResult>`, 1)
	scan = strings.Replace(scan, "<TestResult>", `<Group id="g"><Rule id="ssg_a"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-100</reference></Rule></Group><TestResult>`, 1)
	privateBench(t, host, "run.results.xml", scan)
	privateBench(t, host, "run.report.html", `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">pass</span></div>`)
	privateBench(t, library, "U_RHEL_9_STIG_V2R9_Manual-xccdf.xml", benchmarkFixture("2", "9"))
	newest := privateBench(t, library, "U_RHEL_9_STIG_V2R10_Manual-xccdf.xml", strings.Replace(benchmarkFixture("2", "10"), "SV-100r1_rule", "SV-100r2_rule", 1))
	args := []string{"batch-cklb", "--input-root", root, "--library-root", library}
	var out, errs bytes.Buffer
	if code := run(append(append([]string{}, args...), "--dry-run"), &out, &errs); code != 0 || !strings.Contains(out.String(), newest) {
		t.Fatalf("dry run did not show selected release: %d %q %q", code, out.String(), errs.String())
	}
	if files, _ := filepath.Glob(filepath.Join(host, "*.cklb")); len(files) != 0 {
		t.Fatal("dry run wrote a checklist")
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("conversion failed: %d %q", code, errs.String())
	}
	files, err := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if err != nil || len(files) != 1 {
		t.Fatalf("output files: %v %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	rule := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["rule_id"] != "SV-100r2_rule" || rule["status"] != "not_a_finding" {
		t.Fatalf("wrong benchmark selected: %+v", rule)
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), "SKIP") {
		t.Fatalf("repeat conversion: %d %q %q", code, out.String(), errs.String())
	}
	if code := run(append(append([]string{}, args...), "--benchmark", newest), &out, &errs); code == 0 {
		t.Fatal("simultaneous library and explicit benchmark accepted")
	}
	privateBench(t, library, "U_RHEL_9_STIG_V2R11_Manual-xccdf.xml", strings.Replace(benchmarkFixture("2", "11"), "SV-100r1_rule", "SV-100r3_rule", 1))
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), "CREATED") || !strings.Contains(out.String(), "V2R11") {
		t.Fatalf("new quarterly release not selected on next invocation: %d %q %q", code, out.String(), errs.String())
	}
	files, err = filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if err != nil || len(files) != 2 {
		t.Fatalf("new release replaced or omitted prior result: %v %v", files, err)
	}
}

func TestBatchCLIHelpSucceeds(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"batch-cklb", "--help"}, &out, &errs); code != 0 || !strings.Contains(errs.String(), "input-root") || strings.Contains(errs.String(), "assume-v-sv-equivalence") {
		t.Fatalf("help failed: %d %q", code, errs.String())
	}
}

func TestAssetCheckCLI(t *testing.T) {
	dir := t.TempDir()
	pre := []byte("<synthetic-scan/>")
	prePath := filepath.Join(dir, "pre.xml")
	if err := os.WriteFile(prePath, pre, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(pre)
	record := map[string]any{"schema_version": 1, "cycle_id": "2026-q4", "asset_fqdn": "node.example.test", "os_release": "rhel9", "role": "node", "baseline_state": "clean", "baseline_sha256": strings.Repeat("a", 64), "pre_scan_sha256": hex.EncodeToString(hash[:]), "lab_commit": strings.Repeat("b", 40)}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(dir, "asset.json")
	if err := os.WriteFile(assetPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"asset-check", "--asset", assetPath, "--pre", prePath, "--host", "node.example.test"}
	var out, stderr bytes.Buffer
	if code := run(args, &out, &stderr); code != 0 {
		t.Fatalf("valid record exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), "valid") {
		t.Fatalf("unexpected output: %s", out.String())
	}
	out.Reset()
	stderr.Reset()
	args[len(args)-1] = "other.example.test"
	if code := run(args, &out, &stderr); code == 0 {
		t.Fatal("wrong host accepted")
	}
	if out.Len() != 0 {
		t.Fatal("failure printed success")
	}
	args[len(args)-1] = "node.example.test"
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(assetPath, link); err != nil {
		t.Fatal(err)
	}
	args[2] = link
	out.Reset()
	stderr.Reset()
	if code := run(args, &out, &stderr); code == 0 {
		t.Fatal("symlinked asset accepted")
	}
	args[2] = assetPath
	if err := os.Chmod(prePath, 0644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	stderr.Reset()
	if code := run(args, &out, &stderr); code == 0 {
		t.Fatal("public pre-scan accepted")
	}
}
