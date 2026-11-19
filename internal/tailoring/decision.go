package tailoring

import "strings"

// IsAdminDecision reports whether a checklist status and comment are an
// administrator decision rather than an untouched scanner result.
// Plain passes and not-reviewed placeholders from docket are not decisions.
// A non-empty comment that does not match those generated texts is a decision,
// including a manual status change made in checkmate.
func IsAdminDecision(status, comment string) bool {
	switch status {
	case "open", "not_a_finding", "not_applicable", "not_reviewed":
	default:
		return false
	}
	c := strings.TrimSpace(comment)
	if c == "" || isAutomatedComment(c) {
		return false
	}
	return true
}

func isAutomatedComment(c string) bool {
	switch c {
	case "Not a Finding", "Open", "Not Applicable", "NOT REVIEWED":
		return true
	}
	markers := []string{
		"NOT REVIEWED",
		"XCCDF rule result:",
		"Result of item-state comparison",
		"check result:",
		"item-state result:",
		"OVAL test result:",
		"Automated scan candidate",
		"Automated config candidate",
		"Raw running config SHA-256",
		"Official Cisco benchmark SHA-256",
	}
	for _, m := range markers {
		if strings.Contains(c, m) {
			return true
		}
	}
	return false
}

// WorksheetRow is one checklist rule considered for a partial host worksheet.
type WorksheetRow struct {
	STIGID  string
	SVID    string
	Status  string
	Comment string
}

// HostWorksheet builds a schema v3 host file containing only rows a person
// still has to edit or that an administrator already overrode.
// Scored scan passes are omitted. The file has no benchmark hash.
func HostWorksheet(benchmarkID string, rows []WorksheetRow) []byte {
	f := File{SchemaVersion: SchemaVersion, BenchmarkID: benchmarkID, Layer: Host}
	for _, row := range rows {
		status := row.Status
		comment := strings.TrimSpace(row.Comment)
		switch status {
		case "open", "not_a_finding", "not_applicable":
			if comment == "" || isAutomatedComment(comment) {
				continue
			}
		case "not_reviewed":
			if comment == "" || isAutomatedComment(comment) {
				comment = "Not reviewed. Replace this comment with the local evidence and set status."
			}
		default:
			continue
		}
		f.Rules = append(f.Rules, Rule{STIGID: row.STIGID, SVID: row.SVID, Status: status, Comment: comment})
	}
	if f.Rules == nil {
		f.Rules = []Rule{}
	}
	var b strings.Builder
	b.WriteString("# Partial host tailoring worksheet for " + benchmarkID + ".\n")
	b.WriteString("# Schema version 3. This file has no benchmark_sha256; it inherits the root pin.\n")
	b.WriteString("# Copy it beside the host evidence as " + benchmarkID + ".tailoring.yaml after review.\n")
	b.WriteString("# Drop rows that should keep the scan or config result.\n")
	b.Write(Format(f))
	return []byte(b.String())
}
