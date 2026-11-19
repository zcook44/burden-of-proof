package draft

import (
	"html"
	"regexp"
	"strings"
)

var (
	vulnDiscussion   = regexp.MustCompile(`(?s)<VulnDiscussion>(.*?)</VulnDiscussion>`)
	potentialImpacts = regexp.MustCompile(`(?s)<PotentialImpacts>(.*?)</PotentialImpacts>`)
)

// manualNarrative copies the DISA discussion and potential-impact text out of
// a Rule description. Those blocks are stored as escaped XML inside the
// description element. An empty impact stays empty; the manual is not padded.
func manualNarrative(description string) (discussion, impact string) {
	text := html.UnescapeString(description)
	return tagText(vulnDiscussion, text), tagText(potentialImpacts, text)
}

func tagText(pattern *regexp.Regexp, text string) string {
	match := pattern.FindStringSubmatch(text)
	if match == nil {
		return ""
	}
	return strings.TrimSpace(match[1])
}
