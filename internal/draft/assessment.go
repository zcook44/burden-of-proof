package draft

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
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
	result, err := renderAssessment(report, doc, checks, host, operatorApproved, ":arf")
	if err != nil {
		return nil, err
	}
	result["id"] = uuid5(result["id"].(string) + ":arf:" + hash(arfBytes))
	return result, nil
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
	label := "STIG CHECKLIST"
	mode := ":assessment-readable-v4" + evidenceMode
	if operatorApproved {
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

// assessmentRule keeps the candidate status separate from individual OVAL
// outcomes. A passing negative check can legitimately contain a false item.
func assessmentRule(c reconcile.Control, html map[string]reporthtml.Rule, observed arf.Report) (string, string) {
	label := map[string]string{"not_a_finding": "Not a Finding", "open": "Open", "not_applicable": "Not Applicable", "not_reviewed": "NOT REVIEWED"}[c.Status]
	if label == "" {
		label = "NOT REVIEWED"
	}
	comment := label
	if c.Status == "not_reviewed" {
		comment += " — " + c.Reason
	}
	if len(c.Sources) == 0 {
		return "No matching automated check was available.", comment
	}
	findings, seen := []string{}, map[string]bool{}
	for _, src := range c.Sources {
		rule := observed.Rules[src.RuleID]
		names := map[string]string{}
		for _, check := range html[src.RuleID].Checks {
			if check.ID != "" && check.Name != "" {
				names[check.ID] = check.Name
			}
		}
		if len(rule.Tests) == 0 {
			if len(html[src.RuleID].Checks) == 0 {
				appendDistinct(&findings, seen, "No executed check details or host values were recorded; see the source rule in the provenance file.")
			}
			for i, check := range html[src.RuleID].Checks {
				name := check.Name
				if name == "" {
					name = fmt.Sprintf("Automated test %d", i+1)
				}
				if len(check.Items) == 0 {
					appendDistinct(&findings, seen, fmt.Sprintf("%s — check %s; no item comparison", name, check.Result))
				}
				for _, item := range check.Items {
					if item.Comparison == "not evaluated" {
						appendDistinct(&findings, seen, fmt.Sprintf("%s — check %s; collected: %s", name, check.Result, briefObservation(item.Description)))
					} else {
						appendDistinct(&findings, seen, fmt.Sprintf("%s — check %s; item %s: %s", name, check.Result, item.Comparison, briefObservation(item.Description)))
					}
				}
			}
			continue
		}
		for i, test := range rule.Tests {
			name := names[test.ID]
			if name == "" {
				name = fmt.Sprintf("Automated test %d", i+1)
			}
			if len(test.Items) == 0 {
				if test.ObjectFlag != "" {
					appendDistinct(&findings, seen, fmt.Sprintf("%s — test result %s; %s; no collected value", name, test.Result, objectSummary(test)))
				} else {
					appendDistinct(&findings, seen, fmt.Sprintf("%s — test result %s; no collected item value", name, test.Result))
				}
			}
			for _, item := range test.Items {
				if item.Result == "not evaluated" {
					label := "collected"
					if test.CheckExistence == "all_exist" && test.Result == "true" {
						label = "found"
					}
					appendDistinct(&findings, seen, fmt.Sprintf("%s — test result %s; %s: %s", name, test.Result, label, briefObservation(item.Fields)))
				} else {
					appendDistinct(&findings, seen, fmt.Sprintf("%s — test result %s; observed item %s: %s", name, test.Result, item.Result, briefObservation(item.Fields)))
				}
			}
		}
	}
	return strings.Join(boundEvidence(findings, c.Status, 7), "\n"), comment
}

func objectSummary(test arf.Test) string {
	switch {
	case test.ObjectFlag == "does not exist" && test.CheckExistence == "all_exist":
		return "required object was not found"
	case test.ObjectFlag == "does not exist" && test.CheckExistence == "none_exist":
		return "no object found (absence is expected by this test)"
	default:
		return "object status: " + test.ObjectFlag + " (see raw ARF for test criteria)"
	}
}

// ARF fields are quoted by the collector. Keep recognizable host observations,
// not regex predicates, duplicate paths, or OS metadata. Raw ARF retains all.
var observationField = regexp.MustCompile(`(?:^|; )([a-zA-Z_]+): ("(?:\\.|[^"\\])*"|[^;]*)`)

func briefObservation(raw string) string {
	parts := []string{}
	for _, match := range observationField.FindAllStringSubmatch(raw, -1) {
		switch match[1] {
		case "filepath", "text", "value", "Value", "Path", "Content", "subexpression", "name", "username", "service_name", "content", "status":
		default:
			continue
		}
		value := match[2]
		if strings.HasPrefix(value, `"`) {
			if unquoted, err := strconv.Unquote(value); err == nil {
				value = unquoted
			}
		}
		value = strings.Join(strings.Fields(value), " ")
		if utf8.RuneCountInString(value) > 100 {
			value = string([]rune(value)[:100]) + "… [full value in raw ARF/HTML]"
		}
		parts = append(parts, match[1]+"="+value)
		if len(parts) == 2 {
			break
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "; ")
	}
	if raw == "" {
		return "no collected field value"
	}
	if strings.Contains(raw, ": ") {
		return "additional host data recorded; see original scan report"
	}
	value := strings.Join(strings.Fields(raw), " ")
	if utf8.RuneCountInString(value) > 100 {
		return string([]rune(value)[:100]) + "… [full value in raw ARF/HTML]"
	}
	return value
}

// Display a few observations, prioritizing failed items for open controls.
// The unmodified, complete evidence remains in the private ARF and HTML.
func boundEvidence(lines []string, status string, limit int) []string {
	if len(lines) > limit {
		wanted := "item true"
		if status == "open" {
			wanted = "item false"
		}
		sort.SliceStable(lines, func(i, j int) bool {
			priority := func(s string) int {
				if strings.Contains(s, wanted) {
					return 2
				}
				if status == "open" && strings.Contains(s, "test result false") {
					return 1
				}
				return 0
			}
			return priority(lines[i]) > priority(lines[j])
		})
		omitted := len(lines) - limit
		lines = append(lines[:limit], fmt.Sprintf("... %d more observations in raw ARF/HTML", omitted))
	}
	for i, line := range lines {
		if utf8.RuneCountInString(line) > 320 {
			lines[i] = string([]rune(line)[:320]) + "... [full observation in raw ARF/HTML]"
		}
	}
	return lines
}
