package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// A Cisco policy is a complete, benchmark-hash-pinned inventory. Its auto
// entries are no-ops; only a deliberate non-auto status with a comment is an
// administrator decision. No policy is optional for older workflows.
type ciscoTailoringRule struct {
	STIGID  string `yaml:"stig_id"`
	SVID    string `yaml:"sv_id"`
	Status  string `yaml:"status"`
	Comment string `yaml:"comment"`
}
type ciscoTailoringFile struct {
	SchemaVersion   int                  `yaml:"schema_version"`
	BenchmarkID     string               `yaml:"benchmark_id"`
	BenchmarkSHA256 string               `yaml:"benchmark_sha256"`
	Rules           []ciscoTailoringRule `yaml:"rules"`
}

func loadCiscoTailoring(directory, benchmarkID string, benchmark []byte, doc map[string]any) ([]ciscoTailoringRule, string, []byte, error) {
	path := filepath.Join(directory, benchmarkID+".tailoring.yaml")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, "", nil, nil
	} else if err != nil {
		return nil, "", nil, fmt.Errorf("Cisco tailoring %s: %w", path, err)
	}
	if err := privateLibraryDirectory(directory); err != nil {
		return nil, "", nil, fmt.Errorf("Cisco tailoring library: %w", err)
	}
	data, err := readPrivate(path)
	if err != nil {
		return nil, "", nil, fmt.Errorf("Cisco tailoring %s: %w", path, err)
	}
	var policy ciscoTailoringFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return nil, "", nil, fmt.Errorf("Cisco tailoring %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, "", nil, fmt.Errorf("Cisco tailoring %s: only one YAML document allowed: %v", path, err)
	}
	if policy.SchemaVersion != 1 || policy.BenchmarkID != benchmarkID || policy.BenchmarkSHA256 != sha256Hex(benchmark) || policy.Rules == nil {
		return nil, "", nil, fmt.Errorf("Cisco tailoring %s: benchmark identity/hash, schema version, or rules list mismatch", path)
	}
	rows := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)
	if len(policy.Rules) != len(rows) {
		return nil, "", nil, fmt.Errorf("Cisco tailoring %s: incomplete control inventory (expected %d, got %d)", path, len(rows), len(policy.Rules))
	}
	official := map[string]string{}
	for _, item := range rows {
		row := item.(map[string]any)
		official[row["group_id"].(string)] = row["rule_id"].(string)
	}
	seen := map[string]bool{}
	for _, r := range policy.Rules {
		if r.STIGID == "" || seen[r.STIGID] || official[r.STIGID] != r.SVID {
			return nil, "", nil, fmt.Errorf("Cisco tailoring %s: duplicate, unknown or mismatched V/SV control %s", path, r.STIGID)
		}
		seen[r.STIGID] = true
		switch r.Status {
		case "auto":
			if r.Comment != "" {
				return nil, "", nil, fmt.Errorf("Cisco tailoring %s: auto entry %s must not carry an admin comment", path, r.STIGID)
			}
		case "open", "not_a_finding", "not_applicable", "not_reviewed":
			if strings.TrimSpace(r.Comment) == "" {
				return nil, "", nil, fmt.Errorf("Cisco tailoring %s: admin comment required for override %s", path, r.STIGID)
			}
		default:
			return nil, "", nil, fmt.Errorf("Cisco tailoring %s: invalid status for %s", path, r.STIGID)
		}
	}
	return policy.Rules, path, data, nil
}

// ciscoPolicyDirectory prefers a tailoring file in the device directory so one
// host can be decided without changing the result for every other device.
func ciscoPolicyDirectory(hostDir, benchmarkDir, benchmarkID string) string {
	if hostDir != "" {
		if _, err := os.Lstat(filepath.Join(hostDir, benchmarkID+".tailoring.yaml")); err == nil {
			return hostDir
		}
	}
	return benchmarkDir
}

// suggestCiscoTailoring is the editable per-device inventory. Scored controls
// stay auto. Not Reviewed controls carry the reason an admin replaces.
func suggestCiscoTailoring(benchmarkID string, benchmark []byte, doc map[string]any) ([]byte, error) {
	rows := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)
	policy := ciscoTailoringFile{
		SchemaVersion: 1, BenchmarkID: benchmarkID, BenchmarkSHA256: sha256Hex(benchmark),
		Rules: make([]ciscoTailoringRule, 0, len(rows)),
	}
	for _, item := range rows {
		row := item.(map[string]any)
		rule := ciscoTailoringRule{STIGID: row["group_id"].(string), SVID: row["rule_id"].(string), Status: "auto"}
		if status, comment, ok := administratorOverride(row["comments"].(string)); ok {
			rule.Status = status
			rule.Comment = comment
		} else if row["status"] == "not_reviewed" {
			rule.Status = "not_reviewed"
			rule.Comment = strings.TrimSpace(row["comments"].(string))
			if rule.Comment == "" {
				rule.Comment = "Not Reviewed. Replace this comment with the local evidence and set status."
			}
			rule.Comment += " Tune this row by setting status to not_a_finding, open, or not_applicable and replacing this comment with the evidence used."
		}
		policy.Rules = append(policy.Rules, rule)
	}
	body, err := yaml.Marshal(policy)
	if err != nil {
		return nil, err
	}
	header := "# Per-device tailoring file suggestion for " + benchmarkID + ".\n" +
		"# status auto keeps the running-config result.\n" +
		"# Edit a not_reviewed row, then copy this tailoring file beside scan.running-config as " + benchmarkID + ".tailoring.yaml.\n" +
		"# The next cisco-cklb, cisco-batch, or cisco-xccdf run for that device applies it.\n"
	return append([]byte(header), body...), nil
}

func administratorOverride(comments string) (string, string, bool) {
	const marker = "\nADMINISTRATOR OVERRIDE ("
	index := strings.LastIndex(comments, marker)
	if index < 0 {
		return "", "", false
	}
	rest := comments[index+len(marker):]
	end := strings.Index(rest, "): ")
	if end < 0 {
		return "", "", false
	}
	status, comment := rest[:end], strings.TrimSpace(rest[end+len("): "):])
	switch status {
	case "open", "not_a_finding", "not_applicable", "not_reviewed":
		if comment == "" {
			return "", "", false
		}
		return status, comment, true
	default:
		return "", "", false
	}
}

func applyCiscoTailoring(doc map[string]any, rules []ciscoTailoringRule) []map[string]string {
	rows := map[string]map[string]any{}
	for _, item := range doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any) {
		row := item.(map[string]any)
		rows[row["group_id"].(string)] = row
	}
	overrides := []map[string]string{}
	for _, r := range rules {
		if r.Status == "auto" {
			continue
		}
		row := rows[r.STIGID]
		baseline := row["status"].(string)
		row["status"] = r.Status
		row["comments"] = row["comments"].(string) + "\nADMINISTRATOR OVERRIDE (" + r.Status + "): " + strings.TrimSpace(r.Comment)
		row["finding_details"] = row["finding_details"].(string) + "\nAutomated config candidate before administrator override: " + baseline + ". Administrator-selected status: " + r.Status + "."
		overrides = append(overrides, map[string]string{"group_id": r.STIGID, "rule_id": r.SVID, "candidate": baseline, "status": r.Status})
	}
	return overrides
}
