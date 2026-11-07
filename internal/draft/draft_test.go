package draft

import (
	"strings"
	"testing"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

const benchmark = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG"><title>RHEL 9 STIG</title><version>2</version><Group id="V-100"><title>Group title</title><Rule id="SV-100r2_rule" severity="high"><title>Rule title</title><version>RHEL-09-111111</version></Rule></Group></Benchmark>`
const scan = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL-9"><Group id="source"><Rule id="ssg_a"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-100</reference></Rule></Group><TestResult><target>node.example.test</target><profile idref="xccdf_org.ssgproject.content_profile_stig"/><rule-result idref="ssg_a"><result>pass</result></rule-result></TestResult></Benchmark>`

func TestAssumedEquivalenceMapsOnlyUnambiguousPassAndFail(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{{"pass", "not_a_finding"}, {"fail", "open"}, {"notapplicable", "not_applicable"}, {"notchecked", "not_reviewed"}} {
		t.Run(tc.raw, func(t *testing.T) {
			source := strings.Replace(scan, ">pass</result>", ">"+tc.raw+"</result>", 1)
			report, err := reconcile.Convert([]byte(source), []byte(benchmark))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := BuildMapped(report, []byte(benchmark))
			if err != nil {
				t.Fatal(err)
			}
			rule := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
			if rule["status"] != tc.want {
				t.Fatalf("raw %s produced %v", tc.raw, rule["status"])
			}
		})
	}
}

func TestAssumedAndUnreviewedDraftsHaveDistinctChecklistIDs(t *testing.T) {
	report, err := reconcile.Convert([]byte(scan), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	unreviewed, err := Build(report, []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	assumed, err := BuildMapped(report, []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	if unreviewed["id"] == assumed["id"] {
		t.Fatal("distinct review states share checklist ID")
	}
}

func TestDraftKeepsCandidatePassUnreviewedAndExactOfficialIDs(t *testing.T) {
	report, err := reconcile.Convert([]byte(scan), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Build(report, []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	stigs := doc["stigs"].([]any)
	rules := stigs[0].(map[string]any)["rules"].([]any)
	rule := rules[0].(map[string]any)
	if rule["status"] != "not_reviewed" || rule["rule_id_src"] != "SV-100r2_rule" || rule["group_id_src"] != "V-100" {
		t.Fatalf("unsafe draft: %+v", rule)
	}
	if !strings.Contains(rule["finding_details"].(string), "ssg_a") {
		t.Fatal("source provenance missing")
	}
}

func TestDraftUsesReportComparisonAsCommentsAndExecutedCheckAsFinding(t *testing.T) {
	html := `<html><body><div class="rule-detail"><table><tr><td class="rule-id">ssg_a</td><td class="rule-result">pass</td></tr></table><div class="check-system-details"><div class="panel-body"><h4><span class="label-primary">audit setting is set</span><span class="label-default">oval:check:tst:1</span><span class="label-success">true</span></h4><table><thead><tr><th>Result of item-state comparison</th><th>Path</th><th>Content</th></tr></thead><tbody><tr><td>true</td><td>/etc/audit.conf</td><td>enabled</td></tr></tbody></table></div></div></div></body></html>`
	report, err := reconcile.Convert([]byte(scan), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := BuildWithReport(report, []byte(benchmark), []byte(html))
	if err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if !strings.Contains(row["comments"].(string), "Result of item-state comparison: true") || !strings.Contains(row["comments"].(string), "Path: /etc/audit.conf") {
		t.Fatalf("comments: %s", row["comments"])
	}
	if !strings.Contains(row["finding_details"].(string), "audit setting is set") || !strings.Contains(row["finding_details"].(string), "oval:check:tst:1") {
		t.Fatalf("finding detail: %s", row["finding_details"])
	}
	if !strings.Contains(row["finding_details"].(string), "numeric V/SV mapping of SSG results") {
		t.Fatal("finding detail omitted the mapping method")
	}
	if !strings.Contains(row["finding_details"].(string), "Path: /etc/audit.conf; Content: enabled") {
		t.Fatal("finding detail omitted observed host value")
	}
	if !strings.Contains(row["comments"].(string), "XCCDF rule result: pass") || !strings.Contains(row["comments"].(string), "check result: true") {
		t.Fatal("comment omitted pass/result context")
	}
}

func TestDraftFailExplainsFailingHostValue(t *testing.T) {
	source := strings.Replace(scan, ">pass</result>", ">fail</result>", 1)
	html := `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">fail</span><div class="check-system-details"><div class="panel-body"><h4><span class="label-primary">verify audit setting</span><span class="label-default">oval:check:tst:1</span><span class="label-danger">false</span></h4><table><thead><tr><th>Result of item-state comparison</th><th>Path</th><th>Content</th></tr></thead><tbody><tr><td>false</td><td>/etc/audit.conf</td><td>disabled</td></tr></tbody></table></div></div></div>`
	report, err := reconcile.Convert([]byte(source), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := BuildWithReport(report, []byte(benchmark), []byte(html))
	if err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["status"] != "open" || !strings.Contains(row["comments"].(string), "XCCDF rule result: fail; check result: false; Result of item-state comparison: false; Path: /etc/audit.conf; Content: disabled") || !strings.Contains(row["finding_details"].(string), "Content: disabled") {
		t.Fatalf("failing value lost: %+v", row)
	}
}

func TestDraftRejectsReportResultMismatch(t *testing.T) {
	html := `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">fail</span></div>`
	report, err := reconcile.Convert([]byte(scan), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildWithReport(report, []byte(benchmark), []byte(html)); err == nil {
		t.Fatal("mismatched report accepted")
	}
}

func TestDraftWithARFUsesCollectedHostValueAndReturnResult(t *testing.T) {
	html := `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">pass</span></div>`
	arfXML := `<asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1"><reports><report id="xccdf1"><content><TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"><target>node.example.test</target><rule-result idref="ssg_a"><result>pass</result><check><check-content-ref href="#oval0" name="oval:def:1"/></check></rule-result></TestResult></content></report><report id="oval0"><content><oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5"><oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><tests><sysctl_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" id="oval:test:tst:1"><object object_ref="oval:obj:1"/></sysctl_test></tests></oval_definitions><results><system><definitions><definition definition_id="oval:def:1" result="true"><criteria><criterion test_ref="oval:test:tst:1"/></criteria></definition></definitions><tests><test test_id="oval:test:tst:1" result="true"><tested_item item_id="101" result="true"/></test></tests><oval_system_characteristics xmlns="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"><collected_objects><object id="oval:obj:1"><reference item_ref="101"/></object></collected_objects><system_data><sysctl_item xmlns="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#unix" id="101" status="exists"><name>crypto.fips_enabled</name><value>1</value></sysctl_item></system_data></oval_system_characteristics></system></results></oval_results></content></report></reports></asset-report-collection>`
	report, err := reconcile.Convert([]byte(scan), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := BuildWithARF(report, []byte(benchmark), []byte(html), []byte(arfXML))
	if err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["status"] != "not_a_finding" || !strings.Contains(row["finding_details"].(string), `value: "1"`) || !strings.Contains(row["comments"].(string), "item-state result: true") || !strings.Contains(row["comments"].(string), `value: "1"`) {
		t.Fatalf("ARF value absent: %+v", row)
	}
}

func TestDraftWithARFReportsVerifiedAbsentObjectWithoutInventingItem(t *testing.T) {
	html := `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">pass</span></div>`
	arfXML := `<asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1"><reports><report id="xccdf1"><content><TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"><target>node.example.test</target><rule-result idref="ssg_a"><result>pass</result><check><check-content-ref href="#oval0" name="oval:def:1"/></check></rule-result></TestResult></content></report><report id="oval0"><content><oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5"><oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><tests><sysctl_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" id="oval:test:tst:1"><object object_ref="oval:obj:1"/></sysctl_test></tests></oval_definitions><results><system><definitions><definition definition_id="oval:def:1" result="true"><criteria><criterion test_ref="oval:test:tst:1"/></criteria></definition></definitions><tests><test test_id="oval:test:tst:1" result="true" check_existence="none_exist"/></tests><oval_system_characteristics xmlns="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"><collected_objects><object id="oval:obj:1" flag="does not exist"/></collected_objects></oval_system_characteristics></system></results></oval_results></content></report></reports></asset-report-collection>`
	report, err := reconcile.Convert([]byte(scan), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := BuildWithARF(report, []byte(benchmark), []byte(html), []byte(arfXML))
	if err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if !strings.Contains(row["comments"].(string), "object flag: does not exist") || !strings.Contains(row["comments"].(string), "check_existence: none_exist") || strings.Contains(row["comments"].(string), "returned host value:") {
		t.Fatalf("absence misrepresented: %+v", row)
	}
}

func TestDraftRejectsBenchmarkMismatch(t *testing.T) {
	report, err := reconcile.Convert([]byte(scan), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(report, []byte(benchmark+" ")); err == nil {
		t.Fatal("unbound benchmark accepted")
	}
}
