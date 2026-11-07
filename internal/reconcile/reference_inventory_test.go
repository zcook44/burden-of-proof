package reconcile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReferenceInventoryIncludesEveryResultWithoutPromotingUnmappedOrUnselected(t *testing.T) {
	input := strings.Replace(scan, `</Group>`, `<Rule id="ssg_unmapped"><reference href="https://public.cyber.mil/stigs/srg-stig-tools/">SV-999r17_rule</reference><reference href="https://example.test/other">Original note</reference></Rule><Rule id="ssg_unselected"><reference href="https://public.cyber.mil/stigs/srg-stig-tools/">SV-100r23_rule</reference></Rule><Rule id="ssg_no_refs"/></Group>`, 1)
	input = strings.Replace(input, `</TestResult>`, `<rule-result idref="ssg_unselected"><result>notselected</result></rule-result><rule-result idref="ssg_no_refs"><result>notchecked</result></rule-result><rule-result idref="ssg_unmapped"><result>fail</result></rule-result></TestResult>`, 1)
	report, err := Convert([]byte(input), []byte(official))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.RuleReferences) != 5 {
		t.Fatalf("expected one entry for every rule-result, got %+v", report.RuleReferences)
	}
	wantIDs := []string{"ssg_a", "ssg_b", "ssg_no_refs", "ssg_unmapped", "ssg_unselected"}
	for i, id := range wantIDs {
		if report.RuleReferences[i].RuleID != id {
			t.Fatalf("non-deterministic or incomplete result inventory: %+v", report.RuleReferences)
		}
	}
	unmapped := report.RuleReferences[3]
	if unmapped.Result != "fail" || len(unmapped.OriginalReferences) != 2 ||
		unmapped.OriginalReferences[0] != (SourceReference{Text: "SV-999r17_rule", Href: legacySVRef, JoinKey: "V-999"}) ||
		unmapped.OriginalReferences[1] != (SourceReference{Text: "Original note", Href: "https://example.test/other"}) {
		t.Fatalf("unmatched legacy SV revision/href or non-control reference lost: %+v", unmapped)
	}
	unselected := report.RuleReferences[4]
	if unselected.Result != "notselected" || len(unselected.OriginalReferences) != 1 ||
		unselected.OriginalReferences[0] != (SourceReference{Text: "SV-100r23_rule", Href: legacySVRef, JoinKey: "V-100"}) {
		t.Fatalf("unselected legacy SV revision/href lost: %+v", unselected)
	}
	if report.RuleReferences[2].Result != "notchecked" || len(report.RuleReferences[2].OriginalReferences) != 0 {
		t.Fatalf("reference-free result missing: %+v", report.RuleReferences[2])
	}
	if report.Controls[0].Status != "not_reviewed" || report.Controls[1].Status != "open" || report.Controls[2].Status != "not_reviewed" {
		t.Fatalf("status mapping changed: %+v", report.Controls)
	}
	if len(report.Controls[0].Sources) != 1 || report.Controls[0].Sources[0].RuleID != "ssg_a" {
		t.Fatalf("unselected reference became positive candidate: %+v", report.Controls[0])
	}
	encoded, err := json.Marshal(report)
	if err != nil || !strings.Contains(string(encoded), `"rule_references"`) || !strings.Contains(string(encoded), `"SV-999r17_rule"`) || !strings.Contains(string(encoded), `"SV-100r23_rule"`) {
		t.Fatalf("inventory missing in sidecar JSON: %s (%v)", encoded, err)
	}
}
