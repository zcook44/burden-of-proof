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
	if !strings.Contains(finding, "Check crypto setting") || !strings.Contains(finding, "value=1") || !strings.Contains(comment, "Not a Finding") || !strings.Contains(finding, "observed item true") {
		t.Fatalf("missing evidence: %q / %q", finding, comment)
	}
	if strings.Contains(comment, "value=1") || strings.Count(finding, "value=1") != 1 {
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
	if !strings.Contains(comment, "Open") || !strings.Contains(finding, "value=disabled") || !strings.Contains(finding, "observed item false") || !strings.Contains(finding, "absence is expected") || strings.Contains(comment, "value=disabled") {
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
	if !strings.Contains(finding, "value=decisive-failure") || strings.Contains(comment, "decisive-failure") {
		t.Fatalf("decisive value omitted")
	}
	if !strings.Contains(finding, "more observations in raw ARF/HTML") || len(comment) > 250 || len(finding) > 3000 {
		t.Fatalf("unbounded display: %d / %d", len(finding), len(comment))
	}
}

func TestAssessmentRulePrioritizesFailedTestWithoutItem(t *testing.T) {
	c := reconcile.Control{Status: "open", Sources: []reconcile.Source{{RuleID: "ssg_a", Result: "fail"}}}
	tests := make([]arf.Test, 0, 20)
	for i := 0; i < 19; i++ {
		tests = append(tests, arf.Test{ID: fmt.Sprintf("oval:%d", i), Result: "true", Items: []arf.Item{{Result: "true", Fields: `value: "present"`}}})
	}
	tests = append(tests, arf.Test{ID: "oval:missing", Result: "false", ObjectFlag: "does not exist", CheckExistence: "all_exist"})
	finding, _ := assessmentRule(c, nil, arf.Report{Rules: map[string]arf.Rule{"ssg_a": {Tests: tests}}})
	if !strings.Contains(finding, "required object was not found") || !strings.Contains(finding, "more observations") {
		t.Fatalf("failed test hidden by positive observations: %s", finding)
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
	if row["status"] != "not_a_finding" || !strings.Contains(row["finding_details"].(string), "verify setting") || !strings.Contains(row["comments"].(string), "Not a Finding") || !strings.Contains(row["finding_details"].(string), "enabled") {
		t.Fatalf("HTML-only lost check/result: %+v", row)
	}
	if strings.Contains(doc["title"].(string), "APPROVED") || strings.Contains(doc["title"].(string), "UNSIGNED") || strings.Contains(doc["title"].(string), "NUMERIC V/SV") {
		t.Fatal("checklist title contains workflow or mapping commentary")
	}
	base, err := BuildWithReport(report, []byte(benchmark), []byte(html))
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity := uuid5(base["id"].(string) + ":assessment:html-only")
	if doc["id"] == oldIdentity {
		t.Fatal("readable review reused an older checklist identity")
	}
}

func TestAssessmentRuleKeepsUnreviewedReason(t *testing.T) {
	f, c := assessmentRule(reconcile.Control{Status: "not_reviewed", Reason: "no mapped scan result"}, nil, arf.Report{Rules: map[string]arf.Rule{}})
	if !strings.Contains(c, "NOT REVIEWED") || !strings.Contains(c, "no mapped scan result") || !strings.Contains(f, "No matching automated check") {
		t.Fatalf("unreviewed: %q / %q", f, c)
	}
}

func TestAssessmentRuleDoesNotExposeUnevaluatedExistenceItem(t *testing.T) {
	c := reconcile.Control{Status: "not_a_finding", Sources: []reconcile.Source{{RuleID: "ssg_package", Result: "pass"}}}
	html := map[string]reporthtml.Rule{"ssg_package": {Checks: []reporthtml.Check{{Name: "package crypto-policies is installed", ID: "oval:pkg"}}}}
	host := arf.Report{Rules: map[string]arf.Rule{"ssg_package": {Tests: []arf.Test{{ID: "oval:pkg", Result: "true", CheckExistence: "all_exist", Items: []arf.Item{{Result: "not evaluated", Fields: `name: "crypto-policies"`}}}}}}}
	finding, comment := assessmentRule(c, html, host)
	if comment != "Not a Finding" || !strings.Contains(finding, "package crypto-policies is installed") || !strings.Contains(finding, "name=crypto-policies") || strings.Contains(strings.ToLower(finding), "not evaluated") {
		t.Fatalf("misleading existence observation: %q / %q", finding, comment)
	}
}

func TestAssessmentRuleDoesNotCallUnevaluatedFailureFound(t *testing.T) {
	c := reconcile.Control{Status: "open", Sources: []reconcile.Source{{RuleID: "ssg_package", Result: "fail"}}}
	host := arf.Report{Rules: map[string]arf.Rule{"ssg_package": {Tests: []arf.Test{{Result: "false", CheckExistence: "all_exist", Items: []arf.Item{{Result: "not evaluated", Fields: `name: "crypto-policies"`}}}}}}}
	finding, _ := assessmentRule(c, nil, host)
	if !strings.Contains(finding, "test result false") || !strings.Contains(finding, "collected: name=crypto-policies") || strings.Contains(finding, "found:") || strings.Contains(finding, "not evaluated") {
		t.Fatalf("failed existence check misreported: %q", finding)
	}
}

func TestAssessmentRuleHTMLFallbackDoesNotExposeUnevaluatedItem(t *testing.T) {
	c := reconcile.Control{Status: "not_a_finding", Sources: []reconcile.Source{{RuleID: "ssg_package", Result: "pass"}}}
	html := map[string]reporthtml.Rule{"ssg_package": {Checks: []reporthtml.Check{{Name: "package crypto-policies is installed", Result: "true", Items: []reporthtml.Item{{Comparison: "not evaluated", Description: `name: "crypto-policies"`}}}}}}
	finding, _ := assessmentRule(c, html, arf.Report{})
	if !strings.Contains(finding, "collected: name=crypto-policies") || strings.Contains(finding, "not evaluated") {
		t.Fatalf("HTML fallback item wording: %q", finding)
	}
}

func TestAssessmentRuleDisplaysConciseHumanEvidence(t *testing.T) {
	c := reconcile.Control{Status: "open", Sources: []reconcile.Source{{RuleID: "ssg_boot", Result: "fail"}}}
	html := map[string]reporthtml.Rule{"ssg_boot": {Result: "fail", Checks: []reporthtml.Check{{Name: "Check GRUB password", ID: "oval:boot:tst:1"}}}}
	host := arf.Report{Rules: map[string]arf.Rule{"ssg_boot": {Result: "fail", Tests: []arf.Test{
		{ID: "oval:boot:tst:1", Result: "false", ObjectFlag: "does not exist", CheckExistence: "all_exist", ObjectID: "oval:obj:1"},
		{ID: "oval:config:tst:1", Result: "true", Items: []arf.Item{{Result: "not evaluated", Fields: `filepath: "/boot/grub2/grub.cfg"; pattern: "^[\\s]*set.*$"; line: "^[\\s]*set.*$"; text: "set superusers=\\"root\\""`}}},
	}}}}
	finding, comment := assessmentRule(c, html, host)
	if comment != "Open" || !strings.Contains(finding, "Check GRUB password") || !strings.Contains(finding, "required object was not found") || !strings.Contains(finding, "/boot/grub2/grub.cfg") || strings.Contains(finding, "not evaluated") {
		t.Fatalf("human-readable evidence missing: %q / %q", finding, comment)
	}
	if strings.Contains(finding+comment, "pattern:") || strings.Contains(finding+comment, "line:") || strings.Contains(finding+comment, "oval:obj:1") || strings.Contains(finding+comment, "oval:config:tst:1") || strings.Contains(comment, "oval:boot:tst:1") || strings.Contains(finding, "check_existence=") || len(finding) > 900 || len(comment) > 250 {
		t.Fatalf("verbose diagnostic leaked into review: %q / %q", finding, comment)
	}
}
