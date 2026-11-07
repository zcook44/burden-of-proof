package draft

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zcook44/burden-of-proof/internal/arf"
	"github.com/zcook44/burden-of-proof/internal/reconcile"
	"github.com/zcook44/burden-of-proof/internal/reporthtml"
)

func TestAssessmentRuleShowsCheckHostValueAndItemOutcomeWithoutBoilerplate(t *testing.T) {
	c := reconcile.Control{Status: "not_a_finding", Sources: []reconcile.Source{{RuleID: "ssg_a", Result: "pass"}}}
	html := map[string]reporthtml.Rule{"ssg_a": {Result: "pass", Checks: []reporthtml.Check{{Name: "Check crypto setting", ID: "oval:test:1", Result: "true"}}}}
	observed := arf.Report{Rules: map[string]arf.Rule{"ssg_a": {Result: "pass", Tests: []arf.Test{{ID: "oval:test:1", Result: "true", Items: []arf.Item{{Result: "true", Fields: `value: "1"`}, {Result: "true", Fields: `value: "1"`}}}}}}}
	finding, comment := assessmentRule(c, html, observed)
	if !strings.Contains(finding, "Check crypto setting") || !strings.Contains(finding, `value: "1"`) || !strings.Contains(comment, "PASS") || !strings.Contains(comment, "item true") || !strings.Contains(comment, `value: "1"`) {
		t.Fatalf("missing evidence: %q / %q", finding, comment)
	}
	if strings.Count(comment, `value: "1"`) != 1 || strings.Count(finding, `value: "1"`) != 1 {
		t.Fatalf("duplicates: %q / %q", finding, comment)
	}
	for _, fluff := range []string{"SHA-256", "DRAFT", "Candidate outcome", "Mapping reason", "references:"} {
		if strings.Contains(finding+comment, fluff) {
			t.Fatalf("boilerplate %q", fluff)
		}
	}
}
func TestAssessmentRuleShowsFailingValueAndAbsentObjectHonestly(t *testing.T) {
	c := reconcile.Control{Status: "open", Sources: []reconcile.Source{{RuleID: "ssg_bad", Result: "fail"}, {RuleID: "ssg_missing", Result: "pass"}}}
	seen := arf.Report{Rules: map[string]arf.Rule{"ssg_bad": {Result: "fail", Tests: []arf.Test{{ID: "oval:bad", Result: "false", Items: []arf.Item{{Result: "false", Fields: `value: "disabled"`}}}}}, "ssg_missing": {Result: "pass", Tests: []arf.Test{{ID: "oval:absent", Result: "true", ObjectID: "oval:obj", ObjectFlag: "does not exist", CheckExistence: "none_exist"}}}}}
	finding, comment := assessmentRule(c, nil, seen)
	if !strings.Contains(comment, "FAIL") || !strings.Contains(comment, `value: "disabled"`) || !strings.Contains(comment, "item false") || !strings.Contains(finding, "does not exist") || !strings.Contains(comment, "no collected item value") {
		t.Fatalf("failed/absent evidence: %q / %q", finding, comment)
	}
}
func TestAssessmentRuleBoundsDisplayAndPrioritizesDecisiveValue(t *testing.T) {
	c := reconcile.Control{Status: "open", Sources: []reconcile.Source{{RuleID: "ssg_a", Result: "fail"}}}
	items := []arf.Item{}
	for i := 0; i < 30; i++ {
		items = append(items, arf.Item{Result: "true", Fields: fmt.Sprintf(`value: "irrelevant-%d"`, i)})
	}
	items = append(items, arf.Item{Result: "false", Fields: `value: "decisive-failure"`})
	observed := arf.Report{Rules: map[string]arf.Rule{"ssg_a": {Result: "fail", Tests: []arf.Test{{ID: "oval:test:1", Result: "false", Items: items}}}}}
	finding, comment := assessmentRule(c, nil, observed)
	if !strings.Contains(comment, `value: "decisive-failure"`) || !strings.Contains(finding, `value: "decisive-failure"`) {
		t.Fatalf("decisive value omitted")
	}
	if !strings.Contains(comment, "additional") || !strings.Contains(finding, "additional") || len(comment) > 10000 || len(finding) > 20000 {
		t.Fatalf("unbounded display: %d / %d", len(finding), len(comment))
	}
}

func TestAssessmentHTMLOnlyScanUsesObservedComparison(t *testing.T) {
	html := `<div class="rule-detail"><span class="rule-id">ssg_a</span><span class="rule-result">pass</span><div class="check-system-details"><div class="panel-body"><h4><span class="label-primary">verify setting</span><span class="label-default">oval:test:tst:1</span><span class="label-success">true</span></h4><table><thead><tr><th>Result of item-state comparison</th><th>Value</th></tr></thead><tbody><tr><td>true</td><td>enabled</td></tr></tbody></table></div></div></div>`
	report, err := reconcile.Convert([]byte(scan), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := BuildAssessmentWithReport(report, []byte(benchmark), []byte(html))
	if err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["status"] != "not_a_finding" || !strings.Contains(row["finding_details"].(string), "verify setting") || !strings.Contains(row["comments"].(string), "PASS") || !strings.Contains(row["comments"].(string), "enabled") {
		t.Fatalf("HTML-only lost check/result: %+v", row)
	}
	if strings.Contains(doc["title"].(string), "APPROVED") {
		t.Fatal("batch falsely approved scan")
	}
}

func TestAssessmentRuleKeepsUnreviewedReason(t *testing.T) {
	f, c := assessmentRule(reconcile.Control{Status: "not_reviewed", Reason: "no mapped scan result"}, nil, arf.Report{Rules: map[string]arf.Rule{}})
	if !strings.Contains(c, "NOT REVIEWED") || !strings.Contains(c, "no mapped scan result") || !strings.Contains(f, "No mapped OpenSCAP check") {
		t.Fatalf("unreviewed: %q / %q", f, c)
	}
}
