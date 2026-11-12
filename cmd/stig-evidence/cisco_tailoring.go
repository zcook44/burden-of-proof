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
