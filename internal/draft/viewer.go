package draft

import (
	"strings"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

// checklistTitle is the name STIG Viewer shows: this host and this benchmark.
func checklistTitle(host, benchmark string) string {
	return host + " - " + benchmark
}

func statusWords(status string) string {
	switch status {
	case "not_a_finding":
		return "Not a Finding"
	case "open":
		return "Open"
	case "not_applicable":
		return "Not Applicable"
	case "not_reviewed":
		return "Not Reviewed"
	default:
		return "Not Reviewed"
	}
}

func sentence(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	runes := []rune(text)
	if runes[0] >= 'a' && runes[0] <= 'z' {
		runes[0] = runes[0] - 'a' + 'A'
	}
	text = string(runes)
	last := runes[len(runes)-1]
	if last == '.' || last == '!' || last == '?' {
		return text
	}
	return text + "."
}

func sentenceFromBrief(brief string) string {
	brief = strings.TrimSpace(brief)
	if brief == "" {
		return ""
	}
	if !strings.Contains(brief, "=") {
		return sentence(brief)
	}
	fields := map[string]string{}
	var order []string
	for _, part := range strings.Split(brief, "; ") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return sentence(brief)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if _, seen := fields[key]; !seen {
			order = append(order, key)
		}
		fields[key] = val
	}
	path, hasPath := lookupField(fields, "Path", "path", "filepath")
	content, hasContent := lookupField(fields, "Content", "content", "text")
	if hasPath && hasContent {
		return "This host's " + path + " has " + content + "."
	}
	name, hasName := lookupField(fields, "name")
	value, hasValue := lookupField(fields, "value", "Value")
	switch {
	case hasName && hasValue:
		return "This host's " + name + " is " + value + "."
	case hasName:
		return "The scan recorded " + name + "."
	case hasValue:
		return "The scan recorded " + value + "."
	}
	if len(order) == 1 {
		key := order[0]
		val := fields[key]
		if val == "" {
			return "The scan recorded " + key + "."
		}
		return "This host's " + key + " is " + val + "."
	}
	return sentence(brief)
}

func lookupField(fields map[string]string, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := fields[key]; ok {
			return value, true
		}
	}
	return "", false
}

func ssgClause(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pass", "passed":
		return "The SSG check passed"
	case "fail", "failed":
		return "An SSG check failed"
	case "notapplicable", "not_applicable", "not applicable":
		return "The mapped SSG checks were not applicable"
	default:
		return "The SSG result did not decide this rule"
	}
}

// rhelComment is the sentence a reviewer reads before the technical lines.
// copied is false when the SSG status stays off the DISA rule.
func rhelComment(status string, copied bool, reason, raw, brief string) string {
	if !copied {
		return "Not Reviewed. The mapped SSG result was " + raw + ". This checklist does not copy that result onto the DISA rule."
	}
	if status == "not_reviewed" && strings.TrimSpace(brief) == "" {
		why := sentence(reason)
		if why == "" {
			return statusWords(status) + "."
		}
		return statusWords(status) + ". " + why
	}
	host := sentenceFromBrief(brief)
	if host == "" {
		host = "No host value was recorded in the scan."
	}
	return statusWords(status) + ". " + host + " " + ssgClause(raw) + "; this is that result placed on the DISA rule id."
}

type observationNote struct {
	line   string
	brief  string
	failed bool
}

func chooseBrief(status string, notes []observationNote) string {
	if status == "open" {
		for _, note := range notes {
			if note.failed && strings.TrimSpace(note.brief) != "" {
				return note.brief
			}
		}
	}
	for _, note := range notes {
		if strings.TrimSpace(note.brief) != "" {
			return note.brief
		}
	}
	return ""
}

func withLines(lead string, lines []string) string {
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			kept = append(kept, line)
		}
	}
	lead = strings.TrimSpace(lead)
	if len(kept) == 0 {
		return lead
	}
	if lead == "" {
		return strings.Join(kept, "\n")
	}
	return lead + "\n\n" + strings.Join(kept, "\n")
}

func firstResult(sources []reconcile.Source) string {
	if len(sources) == 0 {
		return ""
	}
	return sources[0].Result
}

func noteLines(notes []observationNote) []string {
	lines := make([]string, 0, len(notes))
	for _, note := range notes {
		if strings.TrimSpace(note.line) != "" {
			lines = append(lines, note.line)
		}
	}
	return lines
}

// ciscoComment turns an allowlisted observation into the device sentence.
// Tailoring-file instructions are omitted so they are not mistaken for a finding.
func ciscoComment(status, observation string) string {
	text := strings.TrimSpace(observation)
	prefixes := []string{
		"NOT REVIEWED — ",
		"Not a Finding — ",
		"Open — ",
		"Not Applicable — ",
		"Automated config check: ",
	}
	for {
		trimmed := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(text, prefix) {
				text = strings.TrimSpace(strings.TrimPrefix(text, prefix))
				trimmed = true
			}
		}
		if !trimmed {
			break
		}
	}
	text = strings.TrimSpace(strings.TrimSuffix(text, " Manual review of the saved running config is required."))
	text = strings.TrimSpace(strings.TrimSuffix(text, "Manual review of the saved running config is required."))
	text = strings.TrimSpace(cutTailoring(text))
	if text != "" {
		last := []rune(text)
		switch last[len(last)-1] {
		case '.', '!', '?':
		default:
			text += "."
		}
	}
	label := statusWords(status)
	if text == "" {
		return label + ". This is the result of the saved running configuration on this device."
	}
	return label + ". " + text + " This is the result of the saved running configuration on this device."
}

func cutTailoring(text string) string {
	lower := strings.ToLower(text)
	at := strings.Index(lower, "tailoring file")
	if at < 0 {
		return strings.TrimSpace(text)
	}
	cut := at
	for _, sep := range []string{
		", then set the status",
		" and set the status",
		" and replace this comment",
		". confirm no other",
	} {
		if i := strings.Index(lower, sep); i >= 0 && i < cut {
			cut = i
		}
	}
	if cut == at {
		if i := strings.LastIndex(lower[:at], ". "); i >= 0 {
			cut = i
		}
	}
	text = strings.TrimSpace(text[:cut])
	return strings.TrimRight(text, " ,;.")
}
