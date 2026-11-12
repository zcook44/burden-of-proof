package draft

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var ciscoGroupID = regexp.MustCompile(`^V-([0-9]+)$`)
var ciscoRuleID = regexp.MustCompile(`^SV-([0-9]+)r[0-9]+_rule$`)

// officialRuleRow is shared by the scan-based renderer and the conservative
// config renderer so that both retain the same official CKLB rule layout.
func officialRuleRow(stigUUID string, g group, r rule, status, details, comments string) map[string]any {
	return map[string]any{
		"uuid": uuid5(stigUUID + r.ID), "stig_uuid": stigUUID,
		"group_id": g.ID, "group_id_src": g.ID, "rule_id": r.ID, "rule_id_src": r.ID,
		"severity": r.Severity, "weight": r.Weight, "rule_version": r.Version,
		"rule_title": r.Title, "group_title": g.Title, "fix_text": r.Fix,
		"status": status, "finding_details": details, "comments": comments,
	}
}

// BuildCiscoConfig renders a CKLB from a saved running-config and an exact Cisco
// XCCDF. Only pinned, config-decidable checks receive automated verdicts; all
// other checks remain not_reviewed. Raw config content is never copied into the
// checklist; its byte hash binds the identity and finding details.
func BuildCiscoConfig(config []byte, target string, benchmark []byte) (map[string]any, error) {
	if len(bytes.TrimSpace(config)) == 0 || strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("Cisco config and target are required")
	}
	if err := validateCiscoXML(benchmark); err != nil {
		return nil, err
	}
	var b officialBenchmark
	if err := xml.Unmarshal(benchmark, &b); err != nil {
		return nil, err
	}
	if b.XMLName.Space != "http://checklists.nist.gov/xccdf/1.1" || !strings.HasPrefix(b.ID, "Cisco_") || len(b.ID) == len("Cisco_") {
		return nil, fmt.Errorf("expected official Cisco XCCDF 1.1 benchmark")
	}
	name := strings.TrimSpace(b.Title)
	if name == "" {
		return nil, fmt.Errorf("Cisco benchmark title missing")
	}
	benchHash, configHash := hash(benchmark), hash(config)
	stigUUID := uuid5(b.ID + ":" + b.Version + ":" + benchHash)
	rows := []any{}
	groups, rules := map[string]bool{}, map[string]bool{}
	var walk func([]group) error
	walk = func(items []group) error {
		for _, g := range items {
			groupNumber := ciscoGroupID.FindStringSubmatch(g.ID)
			if groupNumber == nil || groups[g.ID] || len(g.Rules) != 1 {
				return fmt.Errorf("invalid or duplicate Cisco group ID/rule inventory: %q", g.ID)
			}
			groups[g.ID] = true
			r := g.Rules[0]
			ruleNumber := ciscoRuleID.FindStringSubmatch(r.ID)
			if ruleNumber == nil || ruleNumber[1] != groupNumber[1] || rules[r.ID] {
				return fmt.Errorf("invalid, duplicate or mismatched Cisco rule ID: %q", r.ID)
			}
			rules[r.ID] = true
			switch r.Severity {
			case "high", "medium", "low", "unknown":
			default:
				return fmt.Errorf("invalid Cisco rule severity: %q", r.Severity)
			}
			status, observation, automatedComment := evaluateCiscoRule(b, g, r, config)
			details := "Raw running config SHA-256: " + configHash + "\nOfficial Cisco benchmark SHA-256: " + benchHash
			comments := automatedComment
			if status == "" {
				status = "not_reviewed"
				details += "\nRunning config alone does not verify this control's complete operational check; manual review required."
				comments = "NOT REVIEWED — raw running config supplied for manual review; no automated pass, finding, or applicability decision asserted."
			} else {
				details += "\n" + observation
			}
			rows = append(rows, officialRuleRow(stigUUID, g, r, status, details, comments))
			if err := walk(g.Groups); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(b.Groups); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("Cisco benchmark has no rules")
	}
	release := ""
	for _, p := range b.Plain {
		if p.ID == "release-info" {
			release = p.Text
		}
	}
	return map[string]any{
		"title":        "DRAFT - AUTO CONFIG VERDICTS - " + target + " - " + name,
		"id":           uuid5(target + ":" + stigUUID + ":" + configHash + ":" + CiscoConfigEvaluatorVersion),
		"cklb_version": "1.0", "target_data": map[string]any{"host_name": target},
		"stigs": []any{map[string]any{"stig_name": name, "display_name": name, "stig_id": b.ID, "release_info": release, "uuid": stigUUID, "size": len(rows), "rules": rows}},
	}, nil
}

// XML unmarshalling of unqualified struct fields accepts unexpected namespaces.
// Validate the full token stream first, including directives and trailing XML.
func validateCiscoXML(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var stack []xml.Name
	roots := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid Cisco benchmark XML: %w", err)
		}
		switch t := token.(type) {
		case xml.Directive:
			return fmt.Errorf("DTD/entity directives forbidden in Cisco benchmark")
		case xml.StartElement:
			if len(stack) == 0 {
				roots++
				if roots != 1 || t.Name.Local != "Benchmark" || t.Name.Space != "http://checklists.nist.gov/xccdf/1.1" {
					return fmt.Errorf("expected XCCDF 1.1 Benchmark root")
				}
			}
			if t.Name.Local == "Group" || t.Name.Local == "Rule" {
				if t.Name.Space != "http://checklists.nist.gov/xccdf/1.1" {
					return fmt.Errorf("foreign namespace on Cisco group/rule")
				}
				if len(stack) == 0 || (t.Name.Local == "Group" && stack[len(stack)-1].Local != "Benchmark" && stack[len(stack)-1].Local != "Group") || (t.Name.Local == "Rule" && stack[len(stack)-1].Local != "Group") {
					return fmt.Errorf("Cisco group/rule outside benchmark inventory")
				}
			}
			stack = append(stack, t.Name)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
	if roots != 1 {
		return fmt.Errorf("Cisco benchmark root missing")
	}
	return nil
}
