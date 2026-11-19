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
	ID          string `xml:"id,attr"`
	Severity    string `xml:"severity,attr"`
	Weight      string `xml:"weight,attr"`
	Title       string `xml:"title"`
	Version     string `xml:"version"`
	Description string `xml:"description"`
	Fix         string `xml:"fixtext"`
	Check       struct {
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
			notes := collectEvidenceNotes(candidate, evidence, observations)
			status := "not_reviewed"
			copied := false
			if assumeEquivalent {
				copied = true
				if candidate.Status == "not_a_finding" || candidate.Status == "open" || candidate.Status == "not_applicable" {
					status = candidate.Status
				}
			}
			comment := rhelComment(status, copied, candidate.Reason, firstResult(candidate.Sources), chooseBrief(status, notes))
			rows = append(rows, officialRuleRow(stigUUID, g, r, status, withLines(comment, noteLines(notes)), comment))
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
	if assumeEquivalent {
		mode = "numeric-v-sv-mapping"
	}
	if evidence != nil {
		mode += ":report:" + htmlHash
	}
	_ = arfHash // The ARF hash stays on the provenance sidecar, not in checklist text.
	return map[string]any{"title": checklistTitle(report.Target, name), "id": uuid5(report.Target + ":" + stigUUID + ":" + report.ScanSHA256 + ":" + mode), "cklb_version": "1.0", "target_data": map[string]any{"host_name": report.Target}, "stigs": []any{map[string]any{"stig_name": name, "display_name": name, "stig_id": b.ID, "release_info": release, "uuid": stigUUID, "size": len(rows), "rules": rows}}}, nil
}

func collectEvidenceNotes(candidate reconcile.Control, evidence map[string]reporthtml.Rule, observations *arf.Report) []observationNote {
	notes := []observationNote{}
	for _, s := range candidate.Sources {
		if evidence == nil && observations == nil {
			notes = append(notes, observationNote{line: fmt.Sprintf("SSG rule %s result %s.", s.RuleID, s.Result)})
			continue
		}
		if evidence != nil {
			observed := evidence[s.RuleID]
			if len(observed.Checks) == 0 {
				notes = append(notes, observationNote{line: "No executed check details in HTML report for " + s.RuleID})
			}
			for _, check := range observed.Checks {
				if len(check.Items) == 0 {
					notes = append(notes, observationNote{
						line:   fmt.Sprintf("SSG rule %s check %s (%s) result %s; no item comparison.", s.RuleID, check.Name, check.ID, check.Result),
						failed: check.Result == "false",
					})
				}
				for _, item := range check.Items {
					notes = append(notes, observationNote{
						line:   fmt.Sprintf("SSG rule %s check %s (%s) result %s; item comparison %s: %s", s.RuleID, check.Name, check.ID, check.Result, item.Comparison, item.Description),
						brief:  briefObservation(item.Description),
						failed: item.Comparison == "false",
					})
				}
			}
		}
		if observations != nil {
			arfRule := observations.Rules[s.RuleID]
			if len(arfRule.Tests) == 0 {
				notes = append(notes, observationNote{line: "No joined OVAL test in ARF for " + s.RuleID})
			}
			for _, test := range arfRule.Tests {
				if len(test.Items) == 0 {
					if test.ObjectFlag != "" {
						brief := objectSummary(test)
						notes = append(notes, observationNote{
							line:   fmt.Sprintf("SSG rule %s OVAL test %s result %s; object flag: %s; check_existence: %s; %s", s.RuleID, test.ID, test.Result, test.ObjectFlag, test.CheckExistence, brief),
							brief:  brief,
							failed: test.Result == "false",
						})
					} else {
						notes = append(notes, observationNote{
							line:   fmt.Sprintf("SSG rule %s OVAL test %s result %s; no collected host value in ARF.", s.RuleID, test.ID, test.Result),
							failed: test.Result == "false",
						})
					}
					continue
				}
				for _, item := range test.Items {
					raw := item.Fields
					if raw == "" {
						raw = "collected item has no field value"
					}
					brief := ""
					if item.Fields != "" {
						brief = briefObservation(item.Fields)
					}
					notes = append(notes, observationNote{
						line:   fmt.Sprintf("SSG rule %s OVAL test %s result %s; item result %s; %s", s.RuleID, test.ID, test.Result, item.Result, raw),
						brief:  brief,
						failed: item.Result == "false",
					})
				}
			}
		}
	}
	return notes
}
