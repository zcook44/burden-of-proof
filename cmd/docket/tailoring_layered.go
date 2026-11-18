package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
	"gopkg.in/yaml.v3"
)

// Unified layered tailoring schema for both RHEL and Cisco.
// Root layer: one file per benchmark at library root (full inventory for Cisco, partial for RHEL)
// Host layer: same filename in host directory (always partial, only differences)
//
// Schema rules (unified for RHEL and Cisco):
// - Comment required on every non-auto override (root or host)
// - No comment on root-level auto rows
// - Host-level auto (revert) MUST have comment explaining why
// - Host file should pin benchmark_id and benchmark_sha256 to fail closed on staleness
//
// Merge: root rules, then host rules override per rule (keyed by stig_id/sv_id)

type layeredTailoringRule struct {
	RuleName string `yaml:"rule_name,omitempty"` // RHEL only
	STIGID   string `yaml:"stig_id"`
	SVID     string `yaml:"sv_id"`
	Status   string `yaml:"status"`
	Comment  string `yaml:"comment,omitempty"`
	Origin   string `yaml:"-"` // Internal: "root" or "host" - tracks which layer this rule came from
}

type layeredTailoringFile struct {
	SchemaVersion   int                    `yaml:"schema_version,omitempty"` // Optional for backward compat; 2 for new format
	BenchmarkID     string                 `yaml:"benchmark_id,omitempty"`   // Required for schema v2
	BenchmarkSHA256 string                 `yaml:"benchmark_sha256,omitempty"` // Required for schema v2
	Rules           []layeredTailoringRule `yaml:"rules"`                    // Required
	Layer           string                 `yaml:"-"`                        // Internal: "root" or "host"
}

// Provenance for a single tailoring application
type tailoringProvenance struct {
	RootFile        string              `json:"root_file,omitempty"`
	RootSHA256      string              `json:"root_sha256,omitempty"`
	HostFile        string              `json:"host_file,omitempty"`
	HostSHA256      string              `json:"host_sha256,omitempty"`
	RuleOrigins     map[string]string   `json:"rule_origins"`              // STIG_ID -> "root" or "host"
}

// loadLayeredTailoring loads root and optional host tailoring files and merges them.
// Returns: merged rules, root path, root bytes, host path, host bytes, error
// For RHEL: libraryRoot is the --library-root or dir of --benchmark
//           hostDir is the scan's host directory under --input-root
// For Cisco: libraryRoot is the benchmark directory
//            hostDir is the device directory (beside scan.running-config)
// requireFullRootInventory: if true (for Cisco), root layer must contain all controls
func loadLayeredTailoring(libraryRoot, hostDir, benchmarkID string, benchmarkBytes []byte, report reconcile.Report, requireFullRootInventory bool) (
	[]layeredTailoringRule, string, []byte, string, []byte, error) {

	filename := benchmarkID + ".tailoring.yaml"
	rootPath := filepath.Join(libraryRoot, filename)
	hostPath := filepath.Join(hostDir, filename)

	// Load root layer (optional)
	var rootFile *layeredTailoringFile
	var rootBytes []byte
	if _, err := os.Lstat(rootPath); err == nil {
		rootFile, rootBytes, err = loadTailoringLayer(rootPath, benchmarkID, benchmarkBytes, report, "root", requireFullRootInventory)
		if err != nil {
			return nil, "", nil, "", nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, "", nil, "", nil, fmt.Errorf("root tailoring %s: %w", rootPath, err)
	}

	// Load host layer (optional)
	var hostFile *layeredTailoringFile
	var hostBytes []byte
	if _, err := os.Lstat(hostPath); err == nil {
		// Host layer is always partial (never requires full inventory)
		hostFile, hostBytes, err = loadTailoringLayer(hostPath, benchmarkID, benchmarkBytes, report, "host", false)
		if err != nil {
			return nil, "", nil, "", nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, "", nil, "", nil, fmt.Errorf("host tailoring %s: %w", hostPath, err)
	}

	// Neither file present is OK
	if rootFile == nil && hostFile == nil {
		return nil, "", nil, "", nil, nil
	}

	// Merge: root first, then host overrides
	merged := make([]layeredTailoringRule, 0)
	ruleMap := make(map[string]layeredTailoringRule)

	if rootFile != nil {
		for _, rule := range rootFile.Rules {
			rule.Origin = "root"
			ruleMap[rule.STIGID] = rule
		}
	}

	if hostFile != nil {
		for _, rule := range hostFile.Rules {
			rule.Origin = "host"
			ruleMap[rule.STIGID] = rule // This will override root rules for the same STIG ID
		}
	}

	// Convert map back to slice
	for _, rule := range ruleMap {
		merged = append(merged, rule)
	}

	// Preserve paths
	rootPathRet := ""
	hostPathRet := ""
	if rootFile != nil {
		rootPathRet = rootPath
	}
	if hostFile != nil {
		hostPathRet = hostPath
	}

	return merged, rootPathRet, rootBytes, hostPathRet, hostBytes, nil
}

func loadTailoringLayer(path, benchmarkID string, benchmarkBytes []byte, report reconcile.Report, layer string, requireFullInventory bool) (
	*layeredTailoringFile, []byte, error) {

	data, err := readPrivate(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%s tailoring %s: %w", layer, path, err)
	}

	var policy layeredTailoringFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return nil, nil, fmt.Errorf("%s tailoring %s: %w", layer, path, err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, nil, fmt.Errorf("%s tailoring %s: only one YAML document allowed: %v", layer, path, err)
	}

	if policy.Rules == nil {
		return nil, nil, fmt.Errorf("%s tailoring %s: rules must be a YAML list (use [] for empty)", layer, path)
	}

	// Determine if this is old (v1/implicit) or new (v2) format
	// Old format: no schema_version or schema_version == 1, used for RHEL root-only templates
	// New format: schema_version == 2, required for all new files (root and host, RHEL and Cisco)
	isOldFormat := policy.SchemaVersion == 0 || policy.SchemaVersion == 1

	if isOldFormat {
		// Backward compatibility for old RHEL templates and Cisco v1 files
		// Only allow old format for ROOT layer (templates), not host overrides
		if layer == "host" {
			return nil, nil, fmt.Errorf("%s tailoring %s: host override files must use schema_version 2 with benchmark_id and benchmark_sha256", layer, path)
		}
		// For old root files, infer benchmark_id from report if missing
		if policy.BenchmarkID == "" {
			policy.BenchmarkID = benchmarkID
		}
		// Old format allowed but not validated strictly (maintain backward compat)
	} else if policy.SchemaVersion == 2 {
		// New format: strict validation
		if policy.BenchmarkID != benchmarkID {
			return nil, nil, fmt.Errorf("%s tailoring %s: benchmark_id mismatch (expected %s, got %s)", layer, path, benchmarkID, policy.BenchmarkID)
		}

		expectedSHA := sha256Hex(benchmarkBytes)
		if policy.BenchmarkSHA256 == "" {
			return nil, nil, fmt.Errorf("%s tailoring %s: benchmark_sha256 is required for schema version 2", layer, path)
		}
		if policy.BenchmarkSHA256 != expectedSHA {
			return nil, nil, fmt.Errorf("%s tailoring %s: benchmark_sha256 mismatch (expected %s, got %s); benchmark may have been updated", layer, path, expectedSHA, policy.BenchmarkSHA256)
		}
	} else {
		return nil, nil, fmt.Errorf("%s tailoring %s: unsupported schema_version %d (supported: 1 for legacy root files, 2 for new format)", layer, path, policy.SchemaVersion)
	}

	// Validate full inventory requirement (for Cisco root layer)
	if requireFullInventory && len(policy.Rules) != len(report.Controls) {
		return nil, nil, fmt.Errorf("%s tailoring %s: incomplete control inventory (expected %d, got %d); Cisco root layer requires all rules", layer, path, len(report.Controls), len(policy.Rules))
	}

	// Build map of official controls
	official := make(map[string]string, len(report.Controls))
	for _, c := range report.Controls {
		official[c.GroupID] = c.RuleID
	}

	seen := map[string]bool{}
	for _, rule := range policy.Rules {
		// Validate STIG/SV IDs
		if rule.STIGID == "" || seen[rule.STIGID] {
			return nil, nil, fmt.Errorf("%s tailoring %s: missing or duplicate STIG ID %q", layer, path, rule.STIGID)
		}
		if official[rule.STIGID] != rule.SVID {
			return nil, nil, fmt.Errorf("%s tailoring %s: unknown or mismatched STIG/SV ID %q / %q", layer, path, rule.STIGID, rule.SVID)
		}
		seen[rule.STIGID] = true

		// Validate rule_name for RHEL (optional field)
		if rule.RuleName != "" && !ssgRuleName.MatchString(rule.RuleName) {
			return nil, nil, fmt.Errorf("%s tailoring %s: invalid rule_name %q for %s", layer, path, rule.RuleName, rule.STIGID)
		}

		// Validate status
		switch rule.Status {
		case "auto", "open", "not_a_finding", "not_applicable", "not_reviewed":
		default:
			return nil, nil, fmt.Errorf("%s tailoring %s: invalid status %q for %s", layer, path, rule.Status, rule.STIGID)
		}

		// Comment rules:
		// - Root layer (new format): non-auto rows MUST have comment; auto rows MAY have explanatory comment
		// - Root layer (old format): comments allowed on auto rows (backward compat with existing RHEL templates)
		// - Host layer: ALL rows MUST have comment (including auto reverts)
		comment := strings.TrimSpace(rule.Comment)

		if layer == "root" {
			if !isOldFormat {
				// Schema v2: strict comment rules
				if rule.Status != "auto" && comment == "" {
					return nil, nil, fmt.Errorf("%s tailoring %s: comment required for non-auto override %s", layer, path, rule.STIGID)
				}
				if rule.Status == "auto" && comment != "" {
					return nil, nil, fmt.Errorf("%s tailoring %s: auto entries must not have comments (schema v2); use status override with comment for policy decisions; rule %s", layer, path, rule.STIGID)
				}
			}
			// Old format: lenient, any comment allowed for backward compat
		} else { // host layer
			if comment == "" {
				return nil, nil, fmt.Errorf("%s tailoring %s: comment required for all host overrides (including auto reverts) for %s", layer, path, rule.STIGID)
			}
		}
	}

	policy.Layer = layer
	return &policy, data, nil
}

// applyLayeredTailoring applies merged tailoring rules and tracks provenance
func applyLayeredTailoring(doc map[string]any, report reconcile.Report, rules []layeredTailoringRule, 
	rootPath, hostPath string) (map[string]string, error) {
	
	if len(rules) == 0 {
		return nil, nil
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

	// Track which layer each rule came from
	ruleOrigins := make(map[string]string)

	for _, rule := range rules {
		row, ok := rows[rule.STIGID]
		if !ok || row["rule_id"].(string) != rule.SVID {
			return nil, fmt.Errorf("tailoring control missing or mismatched: %s", rule.STIGID)
		}

		if rule.Status != "auto" {
			row["status"] = rule.Status
		}

		comment := strings.TrimSpace(rule.Comment)
		if comment != "" {
			label := "Administrator checklist decision (" + rule.Status + "): "
			if rule.Status == "auto" {
				label = "Remediation policy note (scan status retained): "
			}
			row["comments"] = row["comments"].(string) + "\n" + label + comment + "\nAutomated scan candidate: " + candidates[rule.STIGID] + "."
		}

		// Track the actual origin from the merge
		ruleOrigins[rule.STIGID] = rule.Origin
	}

	return ruleOrigins, nil
}

// applyCiscoLayeredTailoring applies tailoring for Cisco and returns overrides + rule origins
func applyCiscoLayeredTailoring(doc map[string]any, rules []layeredTailoringRule, rootPath, hostPath string) ([]map[string]string, map[string]string) {
	rows := map[string]map[string]any{}
	for _, item := range doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any) {
		row := item.(map[string]any)
		rows[row["group_id"].(string)] = row
	}

	overrides := []map[string]string{}
	ruleOrigins := make(map[string]string)

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

		// Track the actual origin from the merge
		ruleOrigins[r.STIGID] = r.Origin
	}

	return overrides, ruleOrigins
}
