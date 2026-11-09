package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
	"gopkg.in/yaml.v3"
)

// One optional policy per RHEL major version, stored beside its official
// benchmarks. A status is an administrator's checklist decision, not a scan.
type tailoringRule struct {
	RuleName string `yaml:"rule_name"`
	STIGID   string `yaml:"stig_id"`
	SVID     string `yaml:"sv_id"`
	Status   string `yaml:"status"`
	Comment  string `yaml:"comment"`
}
type tailoringFile struct {
	Rules []tailoringRule `yaml:"rules"`
}

var ssgRuleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// loadTailoring reads the exact per-OS policy once, rejects unknown fields,
// duplicates and stale DISA IDs, and leaves absent OS policies optional.
func loadTailoring(directory string, major int, report reconcile.Report) ([]tailoringRule, string, []byte, error) {
	path := filepath.Join(directory, fmt.Sprintf("RHEL_%d_STIG.tailoring.yaml", major))
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, "", nil, nil
	} else if err != nil {
		return nil, "", nil, fmt.Errorf("tailoring %s: %w", path, err)
	}
	data, err := readPrivate(path)
	if err != nil {
		return nil, "", nil, fmt.Errorf("tailoring %s: %w", path, err)
	}
	var policy tailoringFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return nil, "", nil, fmt.Errorf("tailoring %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, "", nil, fmt.Errorf("tailoring %s: only one YAML document is allowed: %v", path, err)
	}
	if policy.Rules == nil {
		return nil, "", nil, fmt.Errorf("tailoring %s: rules must be a YAML list (use [] for an empty policy)", path)
	}
	if report.DISABenchmark != fmt.Sprintf("RHEL_%d_STIG", major) {
		return nil, "", nil, fmt.Errorf("tailoring %s: OS family mismatch", path)
	}
	official := make(map[string]string, len(report.Controls))
	for _, c := range report.Controls {
		official[c.GroupID] = c.RuleID
	}
	seen := map[string]bool{}
	for _, rule := range policy.Rules {
		if !ssgRuleName.MatchString(rule.RuleName) {
			return nil, "", nil, fmt.Errorf("tailoring %s: invalid rule_name %q", path, rule.RuleName)
		}
		if rule.STIGID == "" || official[rule.STIGID] != rule.SVID || seen[rule.STIGID] {
			return nil, "", nil, fmt.Errorf("tailoring %s: unknown, duplicate or mismatched STIG/SV ID %q / %q", path, rule.STIGID, rule.SVID)
		}
		seen[rule.STIGID] = true
		switch rule.Status {
		case "auto", "open", "not_a_finding", "not_applicable", "not_reviewed":
		default:
			return nil, "", nil, fmt.Errorf("tailoring %s: unsupported status %q for %s", path, rule.Status, rule.STIGID)
		}
		if strings.TrimSpace(rule.Comment) == "" {
			return nil, "", nil, fmt.Errorf("tailoring %s: comment required for %s", path, rule.STIGID)
		}
	}
	return policy.Rules, path, data, nil
}

func applyTailoring(doc map[string]any, report reconcile.Report, rules []tailoringRule) error {
	if len(rules) == 0 {
		return nil
	}
	rows := map[string]map[string]any{}
	for _, value := range doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any) {
		row := value.(map[string]any)
		rows[row["group_id"].(string)] = row
	}
	candidates := map[string]string{}
	for _, c := range report.Controls {
		candidates[c.GroupID] = c.Status
	}
	for _, rule := range rules {
		row, ok := rows[rule.STIGID]
		if !ok || row["rule_id"].(string) != rule.SVID {
			return fmt.Errorf("tailoring control missing or mismatched: %s", rule.STIGID)
		}
		if rule.Status != "auto" {
			row["status"] = rule.Status
		}
		comment := strings.TrimSpace(rule.Comment)
		label := "Administrator checklist decision (" + rule.Status + "): "
		if rule.Status == "auto" {
			label = "Remediation policy note (scan status retained): "
		}
		row["comments"] = row["comments"].(string) + "\n" + label + comment + "\nAutomated scan candidate: " + candidates[rule.STIGID] + "."
	}
	return nil
}
