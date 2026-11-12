package draft

import "strings"

// CiscoConfigEvaluatorVersion changes whenever supported rule logic changes,
// keeping previous CKLBs and provenance immutable across evaluator updates.
const CiscoConfigEvaluatorVersion = "cisco-config-auto-v4"

// evaluateCiscoRule supports only pinned benchmark checks whose full verdict
// follows from global configuration alone. Unrecognized or contradictory
// snapshots remain unreviewed. Observations are constant allowlisted strings:
// never copy arbitrary configuration text (which may contain secrets) into CKLB.
func evaluateCiscoRule(b officialBenchmark, g group, r rule, config []byte) (string, string, string) {
	if b.ID != "Cisco_IOS_XE_Switch_L2S_STIG" || b.Version != "3" {
		return "", "", ""
	}
	release2 := false
	for _, p := range b.Plain {
		s := strings.TrimSpace(p.Text)
		if p.ID == "release-info" && (s == "Release: 2" || strings.HasPrefix(s, "Release: 2 ")) {
			release2 = true
		}
	}
	if !release2 {
		return "", "", ""
	}
	globals := map[string]bool{}
	perInterfaceLoopGuard := false
	bannerDelimiter := ""
	uncertain := false
	for _, line := range strings.Split(string(config), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if bannerDelimiter != "" {
			if strings.Contains(line, bannerDelimiter) {
				bannerDelimiter = ""
			}
			continue
		}
		if strings.HasPrefix(line, "banner ") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				uncertain = true
				break
			}
			delimiter := fields[2]
			remainder := line[strings.Index(line, delimiter)+len(delimiter):]
			if !strings.Contains(remainder, delimiter) {
				bannerDelimiter = delimiter
			}
			continue
		}
		if line == strings.TrimSpace(line) && line != "" {
			globals[line] = true
		}
		if strings.TrimSpace(line) == "spanning-tree guard loop" {
			perInterfaceLoopGuard = true
		}
	}
	if uncertain || bannerDelimiter != "" {
		return "", "", ""
	}
	switch g.ID {
	case "V-220657":
		if r.ID != "SV-220657r856279_rule" || r.Version != "CISC-L2-000110" || r.Title != "The Cisco switch must have STP Loop Guard enabled." || !strings.Contains(r.Check.Content, "spanning-tree loopguard default") || !strings.Contains(r.Check.Content, "If STP Loop Guard is not enabled, this is a finding.") {
			return "", "", ""
		}
		if globals["spanning-tree loopguard default"] && !globals["no spanning-tree loopguard default"] {
			return "not_a_finding", "Automated config-only check: global spanning-tree loopguard default is configured; no contradictory global disable was found. No operational spanning-tree state was observed.", "AUTOMATED CONFIG VERDICT — Not a Finding: STP Loop Guard global command present in the saved running config."
		}
		if globals["no spanning-tree loopguard default"] && !globals["spanning-tree loopguard default"] && !perInterfaceLoopGuard {
			return "open", "Automated config-only check: STP Loop Guard is explicitly disabled globally and no interface-level Loop Guard enable is present in the saved running config. This finding assumes a complete running configuration; live STP state was not observed.", "AUTOMATED CONFIG VERDICT — Open Finding: Loop Guard is explicitly disabled in the saved configuration."
		}
	case "V-220664":
		if r.ID != "SV-220664r539671_rule" || r.Version != "CISC-L2-000180" || r.Title != "The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links." || !strings.Contains(r.Check.Content, "spanning-tree mode rapid-pvst") || !strings.Contains(r.Check.Content, "MSTP") || !strings.Contains(r.Check.Content, "If either RSTP or MSTP has not been implemented where STP is required, this is a finding.") {
			return "", "", ""
		}
		if (globals["spanning-tree mode rapid-pvst"] != globals["spanning-tree mode mst"]) && !globals["spanning-tree mode pvst"] && !globals["no spanning-tree mode"] {
			return "not_a_finding", "Automated config-only check: a global Rapid STP or MSTP mode is configured, satisfying the mode criterion if STP is required. Actual topology and operational state were not observed.", "AUTOMATED CONFIG VERDICT — Not a Finding: the saved running config selects Rapid STP or MSTP globally."
		}
	}
	return "", "", ""
}
