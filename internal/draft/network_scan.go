package draft

import (
	"fmt"

	"github.com/zcook44/burden-of-proof/internal/netxccdf"
)

// BuildFromNetworkScan joins an oscap-style network TestResult to an official
// Cisco benchmark. Statuses come from the scan. The configuration is not scored again.
func BuildFromNetworkScan(benchmark []byte, scan netxccdf.Scan) (map[string]any, error) {
	if err := scan.Identity.Normalize(); err != nil {
		return nil, err
	}
	if scan.Host == "" || scan.Host != scan.Identity.HostName || scan.BenchmarkID == "" || len(scan.Rules) == 0 {
		return nil, fmt.Errorf("network scan result is incomplete")
	}
	doc, err := BuildCiscoConfig([]byte("hostname "+scan.Host+"\nversion 0\nend\n"), scan.Host, benchmark)
	if err != nil {
		return nil, err
	}
	stig := doc["stigs"].([]any)[0].(map[string]any)
	if stig["stig_id"] != scan.BenchmarkID {
		return nil, fmt.Errorf("network scan benchmark %s does not match %s", scan.BenchmarkID, stig["stig_id"])
	}
	rows := stig["rules"].([]any)
	seen := map[string]bool{}
	for _, item := range rows {
		row := item.(map[string]any)
		ruleID := row["rule_id"].(string)
		found, ok := scan.Rules[ruleID]
		if !ok {
			text := ciscoComment("not_reviewed", "The network scan did not select this control.")
			row["status"] = "not_reviewed"
			row["comments"] = text
			row["finding_details"] = text
			continue
		}
		seen[ruleID] = true
		status, ok := netxccdf.ChecklistStatus(found.Result)
		if !ok {
			return nil, fmt.Errorf("network scan result %q for %s is not an XCCDF result", found.Result, ruleID)
		}
		row["status"] = status
		comment := row["comments"].(string)
		if found.Message != "" {
			comment = found.Message
		}
		row["comments"] = comment
		row["finding_details"] = comment + "\n\nNetwork scan result: " + found.Result + "."
	}
	for ruleID := range scan.Rules {
		if !seen[ruleID] {
			return nil, fmt.Errorf("network scan rule %s is not in %s", ruleID, scan.BenchmarkID)
		}
	}
	doc["title"] = checklistTitle(scan.Identity.FQDN, stig["stig_name"].(string))
	doc["id"] = uuid5(scan.Identity.FQDN + ":" + scan.Identity.IPAddress + ":" + scan.Identity.MACAddress + ":network-xccdf:" + scan.BenchmarkID + ":" + scan.ConfigSHA256 + ":" + scan.TailoringSHA256 + ":" + CiscoConfigEvaluatorVersion)
	doc["target_data"] = map[string]any{
		"target_type":     scan.Identity.TargetType,
		"host_name":       scan.Identity.HostName,
		"ip_address":      scan.Identity.IPAddress,
		"mac_address":     scan.Identity.MACAddress,
		"fqdn":            scan.Identity.FQDN,
		"role":            scan.Identity.Role,
		"technology_area": scan.Identity.TechnologyArea,
		"is_web_database": false,
		"comments":        "Device " + scan.Identity.FQDN + " at " + scan.Identity.IPAddress + ", MAC " + scan.Identity.MACAddress + ". Statuses come from the network scan named for this host.",
	}
	return doc, nil
}
