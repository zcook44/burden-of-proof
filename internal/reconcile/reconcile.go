// Package reconcile maps observed SSG outcomes to exact IDs in a supplied DISA
// benchmark. It is an audit aid, not an official DISA assessment or CKLB.
package reconcile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	ssgNS   = "http://checklists.nist.gov/xccdf/1.2"
	disaNS  = "http://checklists.nist.gov/xccdf/1.1"
	vulnRef = "https://www.cyber.mil/stigs/srg-stig-tools#vulnerability_id"
)

var vulnID = regexp.MustCompile(`^V-[0-9]+$`)
var svID = regexp.MustCompile(`^SV-([0-9]+)r[0-9]+_rule$`)

type reference struct {
	Href string `xml:"href,attr"`
	ID   string `xml:",chardata"`
}
type rule struct {
	ID         string      `xml:"id,attr"`
	References []reference `xml:"reference"`
}
type group struct {
	ID     string  `xml:"id,attr"`
	Rules  []rule  `xml:"Rule"`
	Groups []group `xml:"Group"`
}
type result struct {
	ID     string `xml:"idref,attr"`
	Result string `xml:"result"`
}
type testResult struct {
	Targets  []string `xml:"target"`
	Profiles []struct {
		ID string `xml:"idref,attr"`
	} `xml:"profile"`
	Rules []result `xml:"rule-result"`
}
type benchmark struct {
	XMLName xml.Name     `xml:"Benchmark"`
	ID      string       `xml:"id,attr"`
	Version string       `xml:"version"`
	Groups  []group      `xml:"Group"`
	Tests   []testResult `xml:"TestResult"`
}

// Source retains the original SSG result, not a purported DISA scan result.
type Source struct {
	RuleID     string   `json:"ssg_rule_id"`
	Result     string   `json:"raw_result"`
	References []string `json:"vulnerability_references"`
}
type Control struct {
	GroupID string   `json:"disa_group_id"`
	RuleID  string   `json:"disa_rule_id"`
	Status  string   `json:"candidate_status"`
	Reason  string   `json:"reason"`
	Sources []Source `json:"sources"`
}
type Report struct {
	SchemaVersion   int       `json:"schema_version"`
	Target          string    `json:"target"`
	SSGProfile      string    `json:"ssg_profile"`
	SSGBenchmark    string    `json:"ssg_benchmark"`
	DISABenchmark   string    `json:"disa_benchmark"`
	DISAVersion     string    `json:"disa_version"`
	ScanSHA256      string    `json:"scan_sha256"`
	BenchmarkSHA256 string    `json:"benchmark_sha256"`
	Controls        []Control `json:"controls"`
	Unmapped        []string  `json:"unmapped_ssg_rules"`
}

func parse(data []byte, namespace string) (benchmark, error) {
	var b benchmark
	if bytes.Contains(data, []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
		return b, fmt.Errorf("DTD/entity declarations are forbidden")
	}
	if err := xml.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("invalid XCCDF: %w", err)
	}
	if b.XMLName.Space != namespace || b.ID == "" {
		return b, fmt.Errorf("unexpected XCCDF benchmark namespace or ID")
	}
	return b, nil
}
func walk(groups []group, visit func(group)) {
	for _, g := range groups {
		visit(g)
		walk(g.Groups, visit)
	}
}
func digest(data []byte) string { d := sha256.Sum256(data); return hex.EncodeToString(d[:]) }

// Convert produces a conservative ID reconciliation, not official XCCDF results.
// A source that references multiple vulnerabilities cannot prove either control.
func Convert(scan, official []byte) (Report, error) {
	report := Report{SchemaVersion: 1, ScanSHA256: digest(scan), BenchmarkSHA256: digest(official), Controls: []Control{}, Unmapped: []string{}}
	s, err := parse(scan, ssgNS)
	if err != nil {
		return report, err
	}
	d, err := parse(official, disaNS)
	if err != nil {
		return report, err
	}
	if s.ID != "xccdf_org.ssgproject.content_benchmark_RHEL-9" || d.ID != "RHEL_9_STIG" || strings.TrimSpace(d.Version) == "" {
		return report, fmt.Errorf("RHEL 9 benchmark identity/version mismatch")
	}
	if len(s.Tests) != 1 || len(s.Tests[0].Targets) != 1 || strings.TrimSpace(s.Tests[0].Targets[0]) == "" || len(s.Tests[0].Profiles) != 1 {
		return report, fmt.Errorf("exactly one target, profile and TestResult required")
	}
	profile := s.Tests[0].Profiles[0].ID
	if profile != "xccdf_org.ssgproject.content_profile_stig" && profile != "xccdf_org.ssgproject.content_profile_stig_gui" {
		return report, fmt.Errorf("unexpected SSG profile")
	}
	report.Target = s.Tests[0].Targets[0]
	report.SSGProfile = profile
	report.SSGBenchmark = s.ID
	report.DISABenchmark = d.ID
	report.DISAVersion = d.Version
	sourceRules := map[string]rule{}
	var structural error
	walk(s.Groups, func(g group) {
		for _, r := range g.Rules {
			if r.ID == "" || sourceRules[r.ID].ID != "" {
				structural = fmt.Errorf("missing or duplicate SSG rule ID")
			}
			sourceRules[r.ID] = r
		}
	})
	if structural != nil {
		return report, structural
	}
	officialIDs := map[string]bool{}
	officialRules := map[string]bool{}
	walk(d.Groups, func(g group) {
		if len(g.Rules) != 1 {
			structural = fmt.Errorf("DISA group must have exactly one rule")
			return
		}
		ruleID := g.Rules[0].ID
		sv := svID.FindStringSubmatch(ruleID)
		if !vulnID.MatchString(g.ID) || sv == nil || sv[1] != strings.TrimPrefix(g.ID, "V-") || officialIDs[g.ID] || officialRules[ruleID] {
			structural = fmt.Errorf("missing, duplicate or ambiguous DISA group/rule ID")
			return
		}
		officialIDs[g.ID] = true
		officialRules[ruleID] = true
		report.Controls = append(report.Controls, Control{GroupID: g.ID, RuleID: ruleID, Status: "not_reviewed", Reason: "no mapped scan result", Sources: []Source{}})
	})
	if structural != nil || len(report.Controls) == 0 {
		return report, fmt.Errorf("invalid or empty DISA control inventory")
	}
	sort.Slice(report.Controls, func(i, j int) bool { return report.Controls[i].GroupID < report.Controls[j].GroupID })
	indexed := map[string]int{}
	for i, c := range report.Controls {
		indexed[c.GroupID] = i
	}
	related := map[string]map[string]bool{}
	for id, rule := range sourceRules {
		for _, ref := range rule.References {
			if ref.Href == vulnRef {
				v := strings.TrimSpace(ref.ID)
				if officialIDs[v] {
					if related[v] == nil {
						related[v] = map[string]bool{}
					}
					related[v][id] = true
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, rr := range s.Tests[0].Rules {
		if rr.ID == "" || seen[rr.ID] {
			return report, fmt.Errorf("empty or duplicate SSG result ID")
		}
		seen[rr.ID] = true
		rule, ok := sourceRules[rr.ID]
		if !ok {
			return report, fmt.Errorf("SSG result references unknown rule: %s", rr.ID)
		}
		switch rr.Result {
		case "pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational", "fixed":
		default:
			return report, fmt.Errorf("invalid raw result: %s", rr.Result)
		}
		if rr.Result == "notselected" {
			continue
		}
		refs := []string{}
		unique := map[string]bool{}
		for _, ref := range rule.References {
			if ref.Href != vulnRef {
				continue
			}
			id := strings.TrimSpace(ref.ID)
			if !vulnID.MatchString(id) || unique[id] {
				return report, fmt.Errorf("invalid or duplicate vulnerability reference on %s", rr.ID)
			}
			unique[id] = true
			refs = append(refs, id)
		}
		if len(refs) == 0 {
			report.Unmapped = append(report.Unmapped, rr.ID)
			continue
		}
		sort.Strings(refs)
		src := Source{RuleID: rr.ID, Result: rr.Result, References: refs}
		for _, ref := range refs {
			if index, ok := indexed[ref]; ok {
				report.Controls[index].Sources = append(report.Controls[index].Sources, src)
			} else {
				report.Unmapped = append(report.Unmapped, rr.ID+" -> "+ref)
			}
		}
	}
	for i := range report.Controls {
		c := &report.Controls[i]
		if len(c.Sources) == 0 {
			continue
		}
		sort.Slice(c.Sources, func(i, j int) bool { return c.Sources[i].RuleID < c.Sources[j].RuleID })
		c.Reason = "incomplete or ambiguous source mapping"
		if len(c.Sources) != len(related[c.GroupID]) {
			c.Reason = "referenced SSG check was unselected or missing"
			continue
		}
		ambiguous := false
		allPass := true
		allNA := true
		failed := false
		for _, src := range c.Sources {
			if len(src.References) != 1 {
				ambiguous = true
			}
			if src.Result != "pass" {
				allPass = false
			}
			if src.Result != "notapplicable" {
				allNA = false
			}
			if src.Result == "fail" {
				failed = true
			}
		}
		if ambiguous {
			continue
		}
		if failed {
			c.Status = "open"
			c.Reason = "at least one mapped source failed"
		} else if allPass {
			c.Status = "not_a_finding"
			c.Reason = "all mapped sources passed"
		} else if allNA {
			c.Status = "not_applicable"
			c.Reason = "all mapped sources reported notapplicable"
		}
	}
	sort.Strings(report.Unmapped)
	return report, nil
}
