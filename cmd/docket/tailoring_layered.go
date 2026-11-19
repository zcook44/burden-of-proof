package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
	"github.com/zcook44/burden-of-proof/internal/tailoring"
)

// layeredTailoringRule is the in-process rule after root and host files merge.
// Schema version 3 lives in internal/tailoring and is shared with checkmate.
type layeredTailoringRule struct {
	RuleName string
	STIGID   string
	SVID     string
	Status   string
	Comment  string
	Origin   string
}

type tailoringProvenance struct {
	RootFile    string            `json:"root_file,omitempty"`
	RootSHA256  string            `json:"root_sha256,omitempty"`
	HostFile    string            `json:"host_file,omitempty"`
	HostSHA256  string            `json:"host_sha256,omitempty"`
	RuleOrigins map[string]string `json:"rule_origins"`
}

// loadLayeredTailoring reads the optional root file and the optional host file.
// The benchmark pin is checked only on the root file. Host files must not carry one.
func loadLayeredTailoring(libraryRoot, hostDir, benchmarkID string, benchmarkBytes []byte, report reconcile.Report) (
	[]layeredTailoringRule, string, []byte, string, []byte, error) {

	filename := benchmarkID + ".tailoring.yaml"
	rootPath := filepath.Join(libraryRoot, filename)
	hostPath := filepath.Join(hostDir, filename)
	controls := map[string]string{}
	for _, c := range report.Controls {
		controls[c.GroupID] = c.RuleID
	}
	digest := tailoring.SHA256Hex(benchmarkBytes)

	var rootRules []tailoring.Rule
	var rootBytes []byte
	rootFound := false
	if _, err := os.Lstat(rootPath); err == nil {
		data, err := readPrivate(rootPath)
		if err != nil {
			return nil, "", nil, "", nil, fmt.Errorf("root tailoring %s: %w", rootPath, err)
		}
		parsed, err := tailoring.Parse(data, tailoring.Root, rootPath, benchmarkID, digest, controls)
		if err != nil {
			return nil, "", nil, "", nil, err
		}
		rootRules = parsed.Rules
		rootBytes = data
		rootFound = true
	} else if !os.IsNotExist(err) {
		return nil, "", nil, "", nil, fmt.Errorf("root tailoring %s: %w", rootPath, err)
	}

	var hostRules []tailoring.Rule
	var hostBytes []byte
	hostFound := false
	if _, err := os.Lstat(hostPath); err == nil {
		data, err := readPrivate(hostPath)
		if err != nil {
			return nil, "", nil, "", nil, fmt.Errorf("host tailoring %s: %w", hostPath, err)
		}
		parsed, err := tailoring.Parse(data, tailoring.Host, hostPath, benchmarkID, digest, controls)
		if err != nil {
			return nil, "", nil, "", nil, err
		}
		hostRules = parsed.Rules
		hostBytes = data
		hostFound = true
	} else if !os.IsNotExist(err) {
		return nil, "", nil, "", nil, fmt.Errorf("host tailoring %s: %w", hostPath, err)
	}

	merged := tailoring.Merge(rootRules, hostRules)
	out := make([]layeredTailoringRule, len(merged))
	for i, rule := range merged {
		out[i] = layeredTailoringRule{
			RuleName: rule.RuleName, STIGID: rule.STIGID, SVID: rule.SVID,
			Status: rule.Status, Comment: rule.Comment, Origin: rule.Origin,
		}
	}
	rootRet, hostRet := "", ""
	if rootFound {
		rootRet = rootPath
	} else {
		rootBytes = nil
	}
	if hostFound {
		hostRet = hostPath
	} else {
		hostBytes = nil
	}
	return out, rootRet, rootBytes, hostRet, hostBytes, nil
}

func loadTailoringLayer(path, benchmarkID string, benchmarkBytes []byte, report reconcile.Report, layer string) (*tailoring.File, []byte, error) {
	data, err := readPrivate(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%s tailoring %s: %w", layer, path, err)
	}
	controls := map[string]string{}
	for _, c := range report.Controls {
		controls[c.GroupID] = c.RuleID
	}
	parsed, err := tailoring.Parse(data, tailoring.Layer(layer), path, benchmarkID, tailoring.SHA256Hex(benchmarkBytes), controls)
	if err != nil {
		return nil, nil, err
	}
	return parsed, data, nil
}

func applyLayeredTailoring(doc map[string]any, report reconcile.Report, rules []layeredTailoringRule, rootPath, hostPath string) (map[string]string, error) {
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
		ruleOrigins[rule.STIGID] = rule.Origin
	}
	return ruleOrigins, nil
}

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
		ruleOrigins[r.STIGID] = r.Origin
	}
	return overrides, ruleOrigins
}
