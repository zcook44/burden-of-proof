// Package draft builds a schema-shaped CKLB from a candidate mapping.
// This does not constitute a DISA assessment or authorization for release.
package draft

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/zcook44/burden-of-proof/internal/arf"
	"github.com/zcook44/burden-of-proof/internal/reconcile"
	"github.com/zcook44/burden-of-proof/internal/reporthtml"
)

type rule struct {
	ID       string `xml:"id,attr"`
	Severity string `xml:"severity,attr"`
	Weight   string `xml:"weight,attr"`
	Title    string `xml:"title"`
	Version  string `xml:"version"`
	Fix      string `xml:"fixtext"`
	Check    struct {
		Content string `xml:"check-content"`
	} `xml:"check"`
}
type group struct {
	ID     string  `xml:"id,attr"`
	Title  string  `xml:"title"`
	Rules  []rule  `xml:"Rule"`
	Groups []group `xml:"Group"`
}
type plain struct {
	ID   string `xml:"id,attr"`
	Text string `xml:",chardata"`
}
type officialBenchmark struct {
	XMLName xml.Name `xml:"Benchmark"`
	ID      string   `xml:"id,attr"`
	Title   string   `xml:"title"`
	Version string   `xml:"version"`
	Plain   []plain  `xml:"plain-text"`
	Groups  []group  `xml:"Group"`
}

func hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func uuid5(value string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.Sum(append(ns, []byte(value)...))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// Build creates a draft CKLB with EVERY control Not Reviewed. Candidate statuses
// appear only as SSG observations in finding_details, never as DISA findings.
func Build(report reconcile.Report, data []byte) (map[string]any, error) {
	return build(report, data, false)
}

// BuildMapped applies the numeric V/SV mapping to unambiguous candidates.
// It is still an unsigned draft, not proof of semantic check equivalence.
func BuildMapped(report reconcile.Report, data []byte) (map[string]any, error) {
	return build(report, data, true)
}

func BuildWithReport(report reconcile.Report, data, htmlReport []byte) (map[string]any, error) {
	evidence, err := reporthtml.Extract(htmlReport)
	if err != nil {
		return nil, err
	}
	for _, c := range report.Controls {
		for _, source := range c.Sources {
			observed, ok := evidence[source.RuleID]
			if !ok || observed.Result != source.Result {
				return nil, fmt.Errorf("HTML report/XCCDF mismatch for %s", source.RuleID)
			}
		}
	}
	return buildWithEvidence(report, data, true, evidence, hash(htmlReport), nil, "")
}

// BuildWithARF enriches a V/SV-assumed draft with HTML and joined ARF host items.
func BuildWithARF(report reconcile.Report, data, htmlReport, arfBytes []byte) (map[string]any, error) {
	evidence, err := reporthtml.Extract(htmlReport)
	if err != nil {
		return nil, err
	}
	observed, err := arf.Extract(arfBytes)
	if err != nil {
		return nil, err
	}
	if observed.Target != report.Target {
		return nil, fmt.Errorf("ARF target differs from XCCDF target")
	}
	for _, c := range report.Controls {
		for _, source := range c.Sources {
			htmlRule, ok := evidence[source.RuleID]
			if !ok || htmlRule.Result != source.Result {
				return nil, fmt.Errorf("HTML report/XCCDF mismatch for %s", source.RuleID)
			}
			arfRule, ok := observed.Rules[source.RuleID]
			if !ok || arfRule.Result != source.Result {
				return nil, fmt.Errorf("ARF/XCCDF mismatch for %s", source.RuleID)
			}
		}
	}
	return buildWithEvidence(report, data, true, evidence, hash(htmlReport), &observed, hash(arfBytes))
}

func build(report reconcile.Report, data []byte, assumeEquivalent bool) (map[string]any, error) {
	return buildWithEvidence(report, data, assumeEquivalent, nil, "", nil, "")
}

func buildWithEvidence(report reconcile.Report, data []byte, assumeEquivalent bool, evidence map[string]reporthtml.Rule, htmlHash string, observations *arf.Report, arfHash string) (map[string]any, error) {
	if hash(data) != report.BenchmarkSHA256 || report.Target == "" || report.ScanSHA256 == "" {
		return nil, fmt.Errorf("unbound benchmark or scan provenance")
	}
	if bytes.Contains(data, []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
		return nil, fmt.Errorf("DTD/entity declarations forbidden")
	}
	var b officialBenchmark
	if err := xml.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.XMLName.Space != "http://checklists.nist.gov/xccdf/1.1" || b.ID != report.DISABenchmark || b.Version != report.DISAVersion {
		return nil, fmt.Errorf("official benchmark identity mismatch")
	}
	indexed := map[string]reconcile.Control{}
	for _, c := range report.Controls {
		if c.GroupID == "" || c.RuleID == "" || indexed[c.GroupID].GroupID != "" {
			return nil, fmt.Errorf("duplicate or empty candidate ID")
		}
		indexed[c.GroupID] = c
	}
	rows := []any{}
	seen := map[string]bool{}
	stigUUID := uuid5(b.ID + ":" + b.Version + ":" + report.BenchmarkSHA256)
	var issue error
	var walk func([]group)
	walk = func(groups []group) {
		for _, g := range groups {
			if len(g.Rules) != 1 || seen[g.ID] {
				issue = fmt.Errorf("invalid official rule/group inventory")
				continue
			}
			seen[g.ID] = true
			r := g.Rules[0]
			candidate, ok := indexed[g.ID]
			if !ok || candidate.RuleID != r.ID {
				issue = fmt.Errorf("candidate does not match official group/rule ID")
				continue
			}
			if r.Severity != "high" && r.Severity != "medium" && r.Severity != "low" && r.Severity != "unknown" {
				issue = fmt.Errorf("invalid official severity")
				continue
			}
			details := []string{"DRAFT: SSG-to-DISA vulnerability reference only; DISA check equivalence not reviewed.", "SSG scan SHA-256: " + report.ScanSHA256, "DISA benchmark SHA-256: " + report.BenchmarkSHA256, "Candidate outcome (not a DISA result): " + candidate.Status, "Mapping reason: " + candidate.Reason}
			if evidence == nil {
				details = append(details, "No HTML or ARF host observation supplied; only XCCDF rule outcomes are available.")
			}
			if assumeEquivalent {
				details[0] = "DRAFT: numeric V/SV mapping of SSG results; DISA check equivalence not independently verified."
			}
			if evidence != nil {
				details = append(details, "OpenSCAP HTML report SHA-256: "+htmlHash)
			}
			if observations != nil {
				details = append(details, "OpenSCAP ARF SHA-256: "+arfHash)
			}
			comparisons := []string{}
			for _, s := range candidate.Sources {
				details = append(details, fmt.Sprintf("SSG rule %s: %s; references: %s", s.RuleID, s.Result, strings.Join(s.References, ", ")))
				if evidence != nil {
					observed := evidence[s.RuleID]
					if len(observed.Checks) == 0 {
						details = append(details, "No executed check details in HTML report for "+s.RuleID)
					}
					for _, check := range observed.Checks {
						details = append(details, fmt.Sprintf("Executed check for %s: %s; OVAL/test ID: %s; check result: %s", s.RuleID, check.Name, check.ID, check.Result))
						if len(check.Items) == 0 {
							comparisons = append(comparisons, fmt.Sprintf("%s / %s: no item-state comparison in HTML report", s.RuleID, check.ID))
						}
						for _, item := range check.Items {
							comparisons = append(comparisons, fmt.Sprintf("%s / %s — XCCDF rule result: %s; check result: %s; Result of item-state comparison: %s; %s", s.RuleID, check.ID, s.Result, check.Result, item.Comparison, item.Description))
							details = append(details, fmt.Sprintf("Host observed item for %s / %s: %s", s.RuleID, check.ID, item.Description))
						}
					}
				}
				if observations != nil {
					arfRule := observations.Rules[s.RuleID]
					if len(arfRule.Tests) == 0 {
						details = append(details, "No joined OVAL test in ARF for "+s.RuleID)
					}
					for _, test := range arfRule.Tests {
						details = append(details, fmt.Sprintf("ARF executed OVAL test for %s: %s; test result: %s", s.RuleID, test.ID, test.Result))
						if len(test.Items) == 0 {
							if test.ObjectFlag != "" {
								observation := fmt.Sprintf("object %s; object flag: %s; check_existence: %s", test.ObjectID, test.ObjectFlag, test.CheckExistence)
								details = append(details, fmt.Sprintf("ARF collected object for %s / %s: %s", s.RuleID, test.ID, observation))
								comparisons = append(comparisons, fmt.Sprintf("%s / %s — XCCDF rule result: %s; OVAL test result: %s; %s; no collected item value", s.RuleID, test.ID, s.Result, test.Result, observation))
							} else {
								comparisons = append(comparisons, fmt.Sprintf("%s / %s — XCCDF rule result: %s; OVAL test result: %s; no collected host value in ARF", s.RuleID, test.ID, s.Result, test.Result))
							}
						}
						for _, item := range test.Items {
							if item.Fields == "" {
								comparisons = append(comparisons, fmt.Sprintf("%s / %s — XCCDF rule result: %s; OVAL test result: %s; item-state result: %s; collected item has no field value", s.RuleID, test.ID, s.Result, test.Result, item.Result))
								continue
							}
							details = append(details, fmt.Sprintf("ARF host observed output for %s / %s: %s", s.RuleID, test.ID, item.Fields))
							comparisons = append(comparisons, fmt.Sprintf("%s / %s — XCCDF rule result: %s; OVAL test result: %s; item-state result: %s; returned host value: %s", s.RuleID, test.ID, s.Result, test.Result, item.Result, item.Fields))
						}
					}
				}
			}
			status := "not_reviewed"
			caution := "DRAFT only: independently review the official DISA check and SSG mapping; no approval or DISA assessment is asserted."
			if assumeEquivalent {
				caution = "DRAFT: numeric V/SV mapping of SSG results; not an official DISA scan or ISSO-approved finding."
				if candidate.Status == "not_a_finding" || candidate.Status == "open" || candidate.Status == "not_applicable" {
					status = candidate.Status
				}
			}
			if evidence != nil {
				if len(candidate.Sources) == 0 {
					comparisons = append(comparisons, "No mapped SSG rule; no item-state comparison available")
				}
				if len(comparisons) == 0 {
					comparisons = append(comparisons, "No item-state comparison available in HTML report")
				}
				caution = strings.Join(comparisons, "\n") + "\n" + caution
			}
			rows = append(rows, officialRuleRow(stigUUID, g, r, status, strings.Join(details, "\n"), caution))
			walk(g.Groups)
		}
	}
	walk(b.Groups)
	if issue != nil || len(rows) == 0 || len(rows) != len(indexed) {
		return nil, fmt.Errorf("official inventory differs from candidate reconciliation")
	}
	release := ""
	for _, p := range b.Plain {
		if p.ID == "release-info" {
			release = p.Text
		}
	}
	name := strings.TrimSpace(b.Title)
	if name == "" {
		return nil, fmt.Errorf("official benchmark title missing")
	}
	mode := "unreviewed"
	title := "DRAFT - NOT REVIEWED - " + report.Target + " - " + name
	if assumeEquivalent {
		mode = "numeric-v-sv-mapping"
		title = "DRAFT - NUMERIC V/SV MAPPING - " + report.Target + " - " + name
	}
	if evidence != nil {
		mode += ":report:" + htmlHash
		title = "DRAFT - NUMERIC V/SV MAPPING - REPORT EVIDENCE - " + report.Target + " - " + name
	}
	return map[string]any{"title": title, "id": uuid5(report.Target + ":" + stigUUID + ":" + report.ScanSHA256 + ":" + mode), "cklb_version": "1.0", "target_data": map[string]any{"host_name": report.Target}, "stigs": []any{map[string]any{"stig_name": name, "display_name": name, "stig_id": b.ID, "release_info": release, "uuid": stigUUID, "size": len(rows), "rules": rows}}}, nil
}
