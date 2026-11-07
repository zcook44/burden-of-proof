package draft

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/zcook44/burden-of-proof/internal/arf"
	"github.com/zcook44/burden-of-proof/internal/reconcile"
	"github.com/zcook44/burden-of-proof/internal/reporthtml"
)

// BuildAssessmentWithARF renders an assessment layout after the same joins and
// fail-closed checks as BuildWithARF. Approval is an operator attestation, not
// evidence of a signed release or independent DISA-check equivalence review.
func BuildAssessmentWithARF(report reconcile.Report, benchmark, html, arfBytes []byte, operatorApproved bool) (map[string]any, error) {
	doc, err := BuildWithARF(report, benchmark, html, arfBytes)
	if err != nil {
		return nil, err
	}
	checks, err := reporthtml.Extract(html)
	if err != nil {
		return nil, err
	}
	host, err := arf.Extract(arfBytes)
	if err != nil {
		return nil, err
	}
	return renderAssessment(report, doc, checks, host, operatorApproved, ":arf")
}

// BuildAssessmentWithReport supports older scans that saved XCCDF and HTML but no
// ARF. Values here are limited to what OpenSCAP rendered in the HTML report.
func BuildAssessmentWithReport(report reconcile.Report, benchmark, html []byte) (map[string]any, error) {
	doc, err := BuildWithReport(report, benchmark, html)
	if err != nil {
		return nil, err
	}
	checks, err := reporthtml.Extract(html)
	if err != nil {
		return nil, err
	}
	return renderAssessment(report, doc, checks, arf.Report{Rules: map[string]arf.Rule{}}, false, ":html-only")
}

func renderAssessment(report reconcile.Report, doc map[string]any, checks map[string]reporthtml.Rule, host arf.Report, operatorApproved bool, evidenceMode string) (map[string]any, error) {
	indexed := make(map[string]reconcile.Control, len(report.Controls))
	for _, c := range report.Controls {
		indexed[c.GroupID] = c
	}
	stig := doc["stigs"].([]any)[0].(map[string]any)
	for _, value := range stig["rules"].([]any) {
		row := value.(map[string]any)
		c, ok := indexed[row["group_id"].(string)]
		if !ok {
			return nil, fmt.Errorf("missing control for assessment rendering")
		}
		finding, comment := assessmentRule(c, checks, host)
		row["finding_details"], row["comments"] = finding, comment
	}
	label := "OPENSCAP ASSESSMENT (NUMERIC V/SV MAPPING; UNSIGNED)"
	mode := ":assessment" + evidenceMode
	if operatorApproved {
		label = "OPERATOR APPROVED ASSESSMENT (UNSIGNED; NUMERIC V/SV MAPPING)"
		mode += ":operator-approved-unsigned"
	}
	doc["title"] = label + " - " + report.Target + " - " + stig["stig_name"].(string)
	doc["id"] = uuid5(doc["id"].(string) + mode)
	return doc, nil
}

func appendDistinct(lines *[]string, seen map[string]bool, value string) {
	if value != "" && !seen[value] {
		*lines = append(*lines, value)
		seen[value] = true
	}
}

// assessmentRule deliberately distinguishes rule-level pass/fail from individual
// OVAL test/item outcomes. A passing negative check can include false items.
func assessmentRule(c reconcile.Control, html map[string]reporthtml.Rule, observed arf.Report) (string, string) {
	findings, returns := []string{}, []string{}
	fSeen, cSeen := map[string]bool{}, map[string]bool{}
	label := map[string]string{"not_a_finding": "PASS", "open": "FAIL", "not_applicable": "N/A", "not_reviewed": "NOT REVIEWED"}[c.Status]
	if label == "" {
		label = "NOT REVIEWED"
	}
	if c.Status == "not_reviewed" {
		returns = append(returns, label+": "+c.Reason)
	} else {
		returns = append(returns, label+" (OpenSCAP XCCDF)")
	}
	if len(c.Sources) == 0 {
		return "No mapped OpenSCAP check.", strings.Join(returns, "\n")
	}
	for _, src := range c.Sources {
		rule := observed.Rules[src.RuleID]
		names := map[string]string{}
		for _, check := range html[src.RuleID].Checks {
			if check.ID != "" && check.Name != "" {
				names[check.ID] = check.Name
			}
		}
		if len(c.Sources) > 1 || c.Status == "not_reviewed" {
			appendDistinct(&returns, cSeen, fmt.Sprintf("%s: %s", src.RuleID, src.Result))
		}
		if len(rule.Tests) == 0 {
			appendDistinct(&findings, fSeen, "Check: "+src.RuleID)
			if len(html[src.RuleID].Checks) == 0 {
				appendDistinct(&returns, cSeen, "No executed check or host value collected.")
			}
			for _, check := range html[src.RuleID].Checks {
				appendDistinct(&findings, fSeen, fmt.Sprintf("Check: %s (%s)", check.Name, check.ID))
				for _, item := range check.Items {
					appendDistinct(&findings, fSeen, "Observed: "+item.Description)
					appendDistinct(&returns, cSeen, fmt.Sprintf("%s: item %s; %s", check.ID, item.Comparison, item.Description))
				}
			}
			continue
		}
		for _, test := range rule.Tests {
			name := names[test.ID]
			if name == "" {
				name = test.ID
			}
			appendDistinct(&findings, fSeen, fmt.Sprintf("Check: %s (%s)", name, test.ID))
			if len(test.Items) == 0 {
				if test.ObjectFlag != "" {
					obs := fmt.Sprintf("object %s: %s (check_existence=%s)", test.ObjectID, test.ObjectFlag, test.CheckExistence)
					appendDistinct(&findings, fSeen, "Observed: "+obs)
					appendDistinct(&returns, cSeen, fmt.Sprintf("%s: test %s; %s; no collected item value", test.ID, test.Result, obs))
				} else {
					appendDistinct(&returns, cSeen, fmt.Sprintf("%s: test %s; no collected item value", test.ID, test.Result))
				}
			}
			for _, item := range test.Items {
				if item.Fields != "" {
					appendDistinct(&findings, fSeen, "Observed: [item "+item.Result+"] "+item.Fields)
				}
				value := "no collected field value"
				if item.Fields != "" {
					value = item.Fields
				}
				appendDistinct(&returns, cSeen, fmt.Sprintf("%s: test %s; item %s; %s", test.ID, test.Result, item.Result, value))
			}
		}
	}
	return strings.Join(boundEvidence(findings, c.Status, 16), "\n"), strings.Join(boundEvidence(returns, c.Status, 9), "\n")
}

// Keep the first summary/check line. Prioritize decisive items in a long list;
// omission is visible and the complete unmodified observations stay in ARF.
func boundEvidence(lines []string, status string, limit int) []string {
	if len(lines) > limit {
		wanted := "item true"
		if status == "open" {
			wanted = "item false"
		}
		sort.SliceStable(lines[1:], func(i, j int) bool {
			a, b := lines[i+1], lines[j+1]
			return strings.Contains(a, wanted) && !strings.Contains(b, wanted)
		})
		omitted := len(lines) - limit
		lines = append(lines[:limit], fmt.Sprintf("... %d additional observations in raw ARF/HTML", omitted))
	}
	for i, line := range lines {
		if utf8.RuneCountInString(line) > 1800 {
			lines[i] = string([]rune(line)[:1800]) + "... [field truncated; full value in raw ARF/HTML]"
		}
	}
	return lines
}
