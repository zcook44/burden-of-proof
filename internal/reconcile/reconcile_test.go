package reconcile

import (
	"strings"
	"testing"
)

const official = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG"><version>2</version><Group id="V-100"><Rule id="SV-100r2_rule"/></Group><Group id="V-200"><Rule id="SV-200r3_rule"/></Group><Group id="V-300"><Rule id="SV-300r4_rule"/></Group></Benchmark>`
const scan = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL-9"><Group id="source"><Rule id="ssg_a"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-100</reference></Rule><Rule id="ssg_b"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-200</reference></Rule></Group><TestResult><target>node.example.test</target><profile idref="xccdf_org.ssgproject.content_profile_stig"/><rule-result idref="ssg_a"><result>pass</result></rule-result><rule-result idref="ssg_b"><result>fail</result></rule-result></TestResult></Benchmark>`

func TestReconcileUsesExactOfficialIDsWithoutMakingMissingRulePass(t *testing.T) {
	report, err := Convert([]byte(scan), []byte(official))
	if err != nil {
		t.Fatal(err)
	}
	if report.Target != "node.example.test" {
		t.Fatalf("target %q", report.Target)
	}
	if len(report.Controls) != 3 {
		t.Fatalf("controls %d", len(report.Controls))
	}
	want := []struct{ group, rule, status string }{{"V-100", "SV-100r2_rule", "not_a_finding"}, {"V-200", "SV-200r3_rule", "open"}, {"V-300", "SV-300r4_rule", "not_reviewed"}}
	for i, w := range want {
		got := report.Controls[i]
		if got.GroupID != w.group || got.RuleID != w.rule || got.Status != w.status {
			t.Errorf("control %d: %+v", i, got)
		}
	}
}

func TestReconcileNeverPromotesUnselectedCheckSharingAControl(t *testing.T) {
	extra := strings.Replace(scan, `</Group>`, `<Rule id="ssg_extra"><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-100</reference></Rule></Group>`, 1)
	extra = strings.Replace(extra, `</TestResult>`, `<rule-result idref="ssg_extra"><result>notselected</result></rule-result></TestResult>`, 1)
	report, err := Convert([]byte(extra), []byte(official))
	if err != nil {
		t.Fatal(err)
	}
	if report.Controls[0].Status != "not_reviewed" {
		t.Fatalf("unselected related check promoted: %+v", report.Controls[0])
	}
}

func TestReconcileNeverPromotesAmbiguousMapping(t *testing.T) {
	ambiguous := strings.Replace(scan, `>V-100</reference>`, `>V-100</reference><reference href="https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id">V-300</reference>`, 1)
	report, err := Convert([]byte(ambiguous), []byte(official))
	if err != nil {
		t.Fatal(err)
	}
	if report.Controls[0].Status != "not_reviewed" || report.Controls[2].Status != "not_reviewed" {
		t.Fatalf("ambiguous mapping promoted: %+v", report.Controls)
	}
}

func TestReconcileAllNotApplicableIsCandidateNA(t *testing.T) {
	na := strings.Replace(scan, `<result>pass</result>`, `<result>notapplicable</result>`, 1)
	report, err := Convert([]byte(na), []byte(official))
	if err != nil {
		t.Fatal(err)
	}
	if report.Controls[0].Status != "not_applicable" {
		t.Fatalf("status %s", report.Controls[0].Status)
	}
}

func TestReconcileRejectsMismatchedVAndSVNumbers(t *testing.T) {
	mismatched := strings.Replace(official, `SV-100r2_rule`, `SV-999r2_rule`, 1)
	if _, err := Convert([]byte(scan), []byte(mismatched)); err == nil {
		t.Fatal("V/SV mismatch accepted")
	}
}

func TestReconcileRejectsDuplicateOfficialRuleID(t *testing.T) {
	duplicate := strings.Replace(official, `SV-200r3_rule`, `SV-100r2_rule`, 1)
	if _, err := Convert([]byte(scan), []byte(duplicate)); err == nil {
		t.Fatal("duplicate official rule ID accepted")
	}
}

func TestReconcileRejectsUnknownOrDuplicateSourceIDs(t *testing.T) {
	cases := []string{
		strings.Replace(scan, `idref="ssg_a"`, `idref="unseen"`, 1),
		strings.Replace(scan, `idref="ssg_b"`, `idref="ssg_a"`, 1),
	}
	for _, input := range cases {
		if _, err := Convert([]byte(input), []byte(official)); err == nil {
			t.Fatal("invalid scan accepted")
		}
	}
}
