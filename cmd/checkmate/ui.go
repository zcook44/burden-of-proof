package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/zcook44/checkmate/internal/checklist"
)

// STIG Viewer 3.x uses red Open, green Not a Finding, black Not Applicable,
// and gray Not Reviewed. The black symbol sits on a pale badge for dark terminals.
func statusColor(status string) string {
	switch status {
	case "open":
		return "red"
	case "not_a_finding":
		return "green"
	case "not_applicable":
		return "black"
	case "not_reviewed":
		return "gray"
	default:
		return "gray"
	}
}
func statusBadge(status string) string {
	switch statusColor(status) {
	case "red":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#F07070")).Render("! OPEN")
	case "green":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#67C58F")).Render("✓ NOT A FINDING")
	case "black":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#111111")).Background(lipgloss.Color("#B8B8B8")).Render("⊘ NOT APPLICABLE")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Render("○ NOT REVIEWED")
	}
}
func (m model) pageSize() int { return max(1, min(10, m.height-19)) }
func (m model) selectedRefs() []match {
	visible := m.visible()
	if len(visible) == 0 {
		return nil
	}
	out := []match{}
	for _, ref := range m.groups[visible[m.cursor]].matches {
		if ref.selected {
			out = append(out, ref)
		}
	}
	return out
}
func (m model) selectedCount() int { return len(m.selectedRefs()) }
func (m *model) moveHost(k string, count, page int) {
	if count == 0 {
		m.host = 0
		return
	}
	if page < 1 {
		page = 1
	}
	switch k {
	case "pgdown":
		m.host = min(count-1, m.host+page)
	case "pgup":
		m.host = max(0, m.host-page)
	case "home":
		m.host = 0
	case "end":
		m.host = count - 1
	}
}
func (m model) frame(lines []string) string {
	w := max(40, m.width)
	inner := w - 4
	for i, line := range lines {
		lines[i] = ansi.Truncate(line, inner, "…")
	}
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#718096")).Width(w - 2).Render(strings.Join(lines, "\n"))
}
func (m model) separator() string { return strings.Repeat("─", max(36, m.width-4)) }
func (m model) render() string {
	visible := m.visible()
	schemaMode := "OFF"
	if m.schema != nil {
		schemaMode = "ON"
	}
	lines := []string{fmt.Sprintf("CHECKMATE   %d checklist(s)  ·  %d control groups   Schema: %s", len(m.files), len(m.groups), schemaMode)}
	if m.benchmark != "" {
		lines = append(lines, "Benchmark: "+safe(m.benchmark))
	}
	lines = append(lines, fmt.Sprintf("Status: %s  Severity: %s  Search: %s  Host: %s  %d matches", filters[m.filter], severities[m.severityFilter], safe(m.query), safe(m.hostQuery), len(visible)), m.separator())
	if len(visible) == 0 {
		lines = append(lines, "No matching controls.", m.separator(), "/ STIG search  h host search  f status  F severity  q quit")
		return m.overlayStage(m.frame(lines), group{})
	}
	g := m.groups[visible[m.cursor]]
	r := g.sample
	if m.stage == details {
		return m.renderDetails(g)
	}
	if m.stage == guard {
		return m.renderGuard(g)
	}
	if m.stage == preview {
		return m.renderPreview(g)
	}
	lines = append(lines, fmt.Sprintf("[%d/%d] %s  %s  severity: %s", m.cursor+1, len(visible), safe(r.Benchmark), safe(r.ID), strings.ToUpper(safe(r.Severity))))
	lines = append(lines, fmt.Sprintf("Rule: %s   Release: %s", safe(r.RuleID), safe(r.Release)))
	indices := m.hostIndices(g)
	affected := fmt.Sprintf("Affected checklists   %d selected of %d", m.selectedCount(), len(g.matches))
	if hidden := len(g.matches) - len(indices); m.hostQuery != "" && hidden > 0 {
		affected += fmt.Sprintf("   %d hidden by host search; A selects all %d", hidden, len(g.matches))
	}
	lines = append(lines, "Summary: "+safe(r.Title), m.separator(), affected)
	size, evidenceRows := m.browseSplit(len(indices))
	start := (m.host / size) * size
	end := min(len(indices), start+size)
	for i := start; i < end; i++ {
		ref := g.matches[indices[i]]
		row := m.files[ref.file].Rules[ref.rule]
		selected := " "
		if ref.selected {
			selected = "x"
		}
		focus := " "
		if i == m.host {
			focus = ">"
		}
		host := safe(filepath.Base(filepath.Dir(m.files[ref.file].Path)))
		lines = append(lines, fmt.Sprintf("%s [%s] %-24s  %s", focus, selected, clip(host, 24), statusBadge(row.Status)))
	}
	lines = append(lines, fmt.Sprintf("Hosts %d-%d of %d   PgUp/PgDn pages   Home/End jumps", start+1, end, len(indices)), m.separator())
	focused := g.matches[indices[m.host]]
	current := m.files[focused.file].Rules[focused.rule]
	lines = append(lines, fmt.Sprintf("Focused: %s  %s  %s", safe(m.files[focused.file].Path), statusBadge(current.Status), clip(current.Comment, 40)))
	lines = append(lines, m.browseEvidence(g, evidenceRows)...)
	lines = append(lines, m.separator())
	switch m.stage {
	case browse:
		lines = append(lines, "j/k controls  Tab host  Space select  A all  c none  /,h find  v details  e edit  f/F filters  Esc clears notice  q quit")
	case confirm:
		lines = append(lines, "Y apply   N/Esc cancel   v preview   PgUp/PgDn hosts")
	case search, hostSearch:
		lines = append(lines, "Finder is open")
	case choose:
		lines = append(lines, "State: 1 Open   2 Not a Finding   3 Not Applicable   4 Not Reviewed   Esc cancel")
	case comment:
		lines = append(lines, "New state: "+statusBadge(m.target)+"   Comment (Ctrl+J newline, Enter review, Esc cancel):")
		wrapped := wrapLines(m.note, max(1, m.width-7))
		start := max(0, len(wrapped)-3)
		lines = append(lines, wrapped[start:]...)
		lines = append(lines, "_")
	}
	if m.message != "" {
		lines = append(lines, "Notice: "+safe(m.message))
	}
	return m.overlayStage(m.frame(lines), g)
}
func (m model) overlayStage(framed string, g group) string {
	switch m.stage {
	case confirm:
		page := m.confirmPage()
		dialog := m.confirmDialog(g, page)
		bgH := lipgloss.Height(framed)
		for page > 1 && lipgloss.Height(dialog) > bgH-2 {
			page--
			dialog = m.confirmDialog(g, page)
		}
		return overlayCenter(framed, dialog)
	case search, hostSearch:
		return overlayCenter(framed, m.searchDialog())
	default:
		return framed
	}
}
func (m model) searchDialog() string {
	inner := max(24, m.width-18)
	title := "STIG search"
	prompt := m.query
	n := len(m.visible())
	if m.stage == hostSearch {
		title = "Host search"
		prompt = m.hostQuery
		n = len(m.hostHitFiles())
	}
	page := 8
	if m.height < 30 {
		page = 6
	}
	cur := 0
	if n > 0 {
		cur = min(m.searchCursor, n-1)
	}
	start := 0
	if n > page {
		start = max(0, min(cur-page/2, n-page))
	}
	end := min(n, start+page)
	lines := []string{fmt.Sprintf("%s   %d matches", title, n)}
	if n == 0 {
		lines = append(lines, "  no matches")
	}
	for i := start; i < end; i++ {
		mark := " "
		if i == cur {
			mark = ">"
		}
		lines = append(lines, mark+" "+m.searchRow(i, inner))
	}
	lines = append(lines, "", "> "+safe(prompt)+"_", "Enter accept   Esc cancel   up/down move   ctrl+u clear")
	return lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(lipgloss.Color("#7EB6FF")).Padding(0, 1).Width(inner).Render(strings.Join(lines, "\n"))
}
func (m model) searchRow(i, inner int) string {
	if m.stage == hostSearch {
		f := m.files[m.hostHitFiles()[i]]
		return clip(hostHay(f.Path), max(8, inner-6))
	}
	g := m.groups[m.visible()[i]]
	return fmt.Sprintf("%-14s %-18s %s", clip(g.sample.ID, 14), clip(g.sample.Benchmark, 18), clip(g.sample.Title, max(8, inner-40)))
}
func (m model) confirmPage() int {
	switch {
	case m.height < 28:
		return 3
	case m.height < 36:
		return 4
	default:
		return 5
	}
}
func (m model) confirmDialog(g group, page int) string {
	inner := max(24, m.width-18)
	selected := m.selectedRefs()
	if page < 1 {
		page = 1
	}
	start := 0
	if len(selected) > 0 {
		start = (min(m.host, len(selected)-1) / page) * page
	}
	end := min(len(selected), start+page)
	counts := map[string]int{}
	for _, ref := range selected {
		counts[m.files[ref.file].Rules[ref.rule].Status]++
	}
	lines := []string{"Confirm this change", fmt.Sprintf("%s  %s", safe(g.sample.Benchmark), safe(g.sample.ID)), fmt.Sprintf("%d selected of %d", len(selected), len(g.matches)), fmt.Sprintf("Was  Open %d · Not a Finding %d · Not Applicable %d · Not Reviewed %d", counts["open"], counts["not_a_finding"], counts["not_applicable"], counts["not_reviewed"]), ""}
	if len(selected) == 0 {
		lines = append(lines, "No hosts selected. No files will change.", "", "N/Esc cancel")
	} else {
		oldStatus := m.files[selected[0].file].Rules[selected[0].rule].Status
		oldComment := m.files[selected[0].file].Rules[selected[0].rule].Comment
		uniformStatus, uniformComment := true, true
		for _, ref := range selected[1:] {
			row := m.files[ref.file].Rules[ref.rule]
			if row.Status != oldStatus {
				uniformStatus = false
			}
			if row.Comment != oldComment {
				uniformComment = false
			}
		}
		if uniformStatus {
			lines = append(lines, statusBadge(oldStatus)+"  →  "+statusBadge(m.target))
		} else {
			lines = append(lines, "New state  "+statusBadge(m.target))
		}
		note := clip(strings.ReplaceAll(m.note, "\n", " ↵ "), max(8, inner/2))
		if uniformComment {
			lines = append(lines, clip(oldComment, max(8, inner/2))+"  →  "+note)
		} else {
			lines = append(lines, "New comment  "+note)
		}
		lines = append(lines, "")
		for i := start; i < end; i++ {
			ref := selected[i]
			old := m.files[ref.file].Rules[ref.rule]
			focus := " "
			if i == min(m.host, len(selected)-1) {
				focus = ">"
			}
			lines = append(lines, fmt.Sprintf("%s %-16s %s  →  %s", focus, clip(hostLabel(m.files[ref.file].Path), 16), statusBadge(old.Status), statusBadge(m.target)))
		}
		lines = append(lines, "", fmt.Sprintf("Hosts %d-%d of %d    Nothing is written until Y.", start+1, end, len(selected)), "Provenance sidecars stay stale after Y.", "Y apply    N/Esc cancel    v preview")
	}
	return lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(lipgloss.Color("#E8B86D")).Padding(0, 1).Width(inner).Render(strings.Join(lines, "\n"))
}
func overlayCenter(bg, fg string) string {
	bgLines := strings.Split(bg, "\n")
	fgLines := strings.Split(fg, "\n")
	bgW, fgW := 0, 0
	for _, line := range bgLines {
		bgW = max(bgW, ansi.StringWidth(line))
	}
	for _, line := range fgLines {
		fgW = max(fgW, ansi.StringWidth(line))
	}
	for i, line := range bgLines {
		if gap := bgW - ansi.StringWidth(line); gap > 0 {
			bgLines[i] = line + strings.Repeat(" ", gap)
		}
	}
	row := max(0, (len(bgLines)-len(fgLines))/2)
	for i, line := range fgLines {
		r := row + i
		if r < 0 || r >= len(bgLines) {
			continue
		}
		if gap := fgW - ansi.StringWidth(line); gap > 0 {
			line += strings.Repeat(" ", gap)
		}
		leftEdge := ansi.Truncate(bgLines[r], 1, "")
		rightEdge := ""
		if bgW > 1 {
			rightEdge = ansi.Cut(bgLines[r], bgW-1, bgW)
		}
		innerW := max(0, bgW-ansi.StringWidth(leftEdge)-ansi.StringWidth(rightEdge))
		pad := max(0, (innerW-ansi.StringWidth(line))/2)
		mid := strings.Repeat(" ", pad) + line
		if tail := innerW - ansi.StringWidth(mid); tail > 0 {
			mid += strings.Repeat(" ", tail)
		} else if ansi.StringWidth(mid) > innerW {
			mid = ansi.Truncate(mid, innerW, "")
		}
		bgLines[r] = leftEdge + mid + rightEdge
	}
	return strings.Join(bgLines, "\n")
}
func (m model) renderConfirm(g group) string {
	selected := m.selectedRefs()
	size := m.pageSize()
	start := 0
	if len(selected) > 0 {
		start = (min(m.host, len(selected)-1) / size) * size
	}
	end := min(len(selected), start+size)
	counts := map[string]int{}
	for _, ref := range selected {
		counts[m.files[ref.file].Rules[ref.rule].Status]++
	}
	lines := []string{"CHECKMATE   Review changes", fmt.Sprintf("%s  %s   severity: %s", safe(g.sample.Benchmark), safe(g.sample.ID), strings.ToUpper(safe(g.sample.Severity))), m.separator(), "New state: " + statusBadge(m.target), "New comment: " + safe(strings.ReplaceAll(m.note, "\n", " ↵ ")), fmt.Sprintf("Selected old states: Open %d · Not a Finding %d · Not Applicable %d · Not Reviewed %d", counts["open"], counts["not_a_finding"], counts["not_applicable"], counts["not_reviewed"]), m.separator(), fmt.Sprintf("Affected checklists   %d selected of %d", len(selected), len(g.matches))}
	for i := start; i < end; i++ {
		ref := selected[i]
		path := m.files[ref.file].Path
		old := m.files[ref.file].Rules[ref.rule]
		focus := " "
		if i == m.host {
			focus = ">"
		}
		lines = append(lines, fmt.Sprintf("%s UPDATE %-15s %s -> %s", focus, safe(filepath.Base(filepath.Dir(path))), statusBadge(old.Status), statusBadge(m.target)))
		lines = append(lines, fmt.Sprintf("  Comment: %s -> %s", safe(old.Comment), safe(strings.ReplaceAll(m.note, "\n", " ↵ "))))
	}
	if len(selected) > 0 {
		lines = append(lines, fmt.Sprintf("Selected hosts %d-%d of %d   PgUp/PgDn pages   Home/End jumps", start+1, end, len(selected)))
	} else {
		lines = append(lines, "No hosts selected; no files will change.")
	}
	lines = append(lines, m.separator(), "Existing CKLBs replaced; provenance sidecars remain stale.", "PgUp/PgDn hosts   v full per-host preview   Y/Enter apply   N/Esc cancel")
	return m.frame(lines)
}
func (m model) renderPreview(g group) string {
	selected := m.selectedRefs()
	if len(selected) == 0 {
		return m.renderConfirm(g)
	}
	ref := selected[min(m.host, len(selected)-1)]
	old := m.files[ref.file].Rules[ref.rule]
	content := []string{"Host: " + safe(m.files[ref.file].Path), "Old state: " + statusBadge(old.Status), "Old comment:"}
	content = append(content, wrapLines(old.Comment, max(1, m.width-6))...)
	content = append(content, "", "New state: "+statusBadge(m.target), "New comment:")
	content = append(content, wrapLines(m.note, max(1, m.width-6))...)
	size := max(1, m.height-10)
	start := min(m.detailOffset, max(0, len(content)-1))
	end := min(len(content), start+size)
	lines := []string{fmt.Sprintf("CHECKMATE   Full change preview  host %d/%d", min(m.host, len(selected)-1)+1, len(selected)), m.separator()}
	lines = append(lines, content[start:end]...)
	lines = append(lines, m.separator(), fmt.Sprintf("Lines %d-%d of %d   j/k scroll   PgUp/PgDn pages   Tab next host   Esc return", start+1, end, len(content)))
	return m.frame(lines)
}
func (m model) renderGuard(g group) string {
	lines := []string{"CHECKMATE   Additional authorization", m.separator(), fmt.Sprintf("%s  %s  %d selected hosts", safe(g.sample.Benchmark), safe(g.sample.ID), m.selectedCount()), "Bulk Open -> Not a Finding changes require individual evidence review.", "No files have been written yet.", m.separator(), "Type OVERRIDE and press Enter to apply:", safe(m.ack) + "_", "Esc: return to confirmation"}
	if m.message != "" {
		lines = append(lines, "Notice: "+safe(m.message))
	}
	return m.frame(lines)
}
func wrapLines(s string, width int) []string {
	out := []string{}
	for _, line := range strings.Split(s, "\n") {
		r := []rune(safe(line))
		if len(r) == 0 {
			out = append(out, "")
			continue
		}
		for len(r) > 0 {
			take := min(len(r), max(1, width))
			out = append(out, string(r[:take]))
			r = r[take:]
		}
	}
	return out
}
func (m model) renderDetails(g group) string {
	ref := g.matches[m.hostIndices(g)[m.host]]
	row := m.files[ref.file].Rules[ref.rule]
	width := max(20, m.width-6)
	content := m.evidenceDocument(g, width)
	content = append(content, "", "Comment")
	content = append(content, blockText(row.Comment, width, 2)...)
	size := max(1, m.height-11)
	start := min(m.detailOffset, max(0, len(content)-1))
	end := min(len(content), start+size)
	lines := []string{"CHECKMATE   Check and findings", fmt.Sprintf("%s  %s  %s", safe(row.Benchmark), safe(row.ID), statusBadge(row.Status)), m.separator()}
	lines = append(lines, content[start:end]...)
	lines = append(lines, fmt.Sprintf("Details lines %d-%d of %d", start+1, end, len(content)), m.separator(), "j/k scroll  PgUp/PgDn page  Home first  Esc/v return")
	return m.frame(lines)
}
func (m model) browseSplit(hosts int) (hostRows, evidenceRows int) {
	// Border, titles, separators, focused line, and the key hint sit outside the host list and the evidence panel.
	fixed := 15
	if m.benchmark != "" {
		fixed++
	}
	if m.message != "" {
		fixed++
	}
	room := m.height - fixed
	if room < 4 {
		return 1, max(1, room-1)
	}
	hostRows = min(6, max(1, room/3), max(1, hosts))
	evidenceRows = room - hostRows
	if evidenceRows > 18 {
		evidenceRows = 18
	}
	return hostRows, evidenceRows
}
func (m model) evidenceRefs(g group) []match {
	selected := []match{}
	for _, ref := range g.matches {
		if ref.selected {
			selected = append(selected, ref)
		}
	}
	if len(selected) > 0 {
		return selected
	}
	indices := m.hostIndices(g)
	if len(indices) == 0 || m.host < 0 || m.host >= len(indices) {
		return nil
	}
	return []match{g.matches[indices[m.host]]}
}
func hostLabel(path string) string {
	return filepath.Base(filepath.Dir(path))
}

type textGroup struct {
	label string
	text  string
}

func (m model) groupField(refs []match, field func(checklist.Rule) string) []textGroup {
	order := []string{}
	hosts := map[string][]string{}
	text := map[string]string{}
	for _, ref := range refs {
		row := m.files[ref.file].Rules[ref.rule]
		value := field(row)
		key := strings.TrimSpace(value)
		if _, ok := hosts[key]; !ok {
			order = append(order, key)
			text[key] = strings.TrimRight(value, "\n")
		}
		hosts[key] = append(hosts[key], hostLabel(m.files[ref.file].Path))
	}
	out := make([]textGroup, 0, len(order))
	width := max(16, m.width-10)
	for _, key := range order {
		out = append(out, textGroup{label: joinHosts(hosts[key], width), text: text[key]})
	}
	return out
}
func joinHosts(names []string, width int) string {
	if len(names) == 0 {
		return ""
	}
	s := names[0]
	for i := 1; i < len(names); i++ {
		next := s + ", " + names[i]
		if len([]rune(next)) > width {
			return fmt.Sprintf("%s +%d", s, len(names)-i)
		}
		s = next
	}
	return s
}
func blockText(text string, width, indent int) []string {
	prefix := strings.Repeat(" ", indent)
	if strings.TrimSpace(text) == "" {
		return []string{prefix + "(none recorded)"}
	}
	wrapped := wrapLines(strings.TrimRight(text, "\n"), max(8, width-indent))
	out := make([]string, len(wrapped))
	for i, line := range wrapped {
		out[i] = prefix + line
	}
	return out
}
func fitLines(lines []string, budget int) []string {
	if budget <= 0 {
		return nil
	}
	if len(lines) <= budget {
		return lines
	}
	if budget == 1 {
		return []string{"… v shows the rest"}
	}
	out := append([]string{}, lines[:budget-1]...)
	return append(out, "… v shows the rest")
}
func packEvidence(required, found []string, budget int) []string {
	if len(required)+len(found) <= budget {
		return append(append([]string{}, required...), found...)
	}
	foundBudget := min(len(found), max(2, (budget*2)/3))
	reqBudget := budget - foundBudget
	if reqBudget < 1 {
		reqBudget = 1
		foundBudget = max(1, budget-1)
	}
	return append(fitLines(required, reqBudget), fitLines(found, foundBudget)...)
}
func (m model) evidenceParts(g group, width int) (required, found []string) {
	refs := m.evidenceRefs(g)
	checks := m.groupField(refs, func(row checklist.Rule) string { return row.Check })
	founds := m.groupField(refs, func(row checklist.Rule) string { return row.Findings })
	required = []string{"Required check"}
	if len(checks) <= 1 {
		text := ""
		if len(checks) == 1 {
			text = checks[0].text
		}
		required = append(required, blockText(text, width, 2)...)
	} else {
		required = append(required, "  Required check differs across selected hosts")
		for _, item := range checks {
			required = append(required, "  "+item.label)
			required = append(required, blockText(item.text, width, 4)...)
		}
	}
	if len(founds) <= 1 {
		label := "Found configuration"
		if len(founds) == 1 {
			label = "Found on " + founds[0].label
		}
		found = []string{label}
		text := ""
		if len(founds) == 1 {
			text = founds[0].text
		}
		found = append(found, blockText(text, width, 2)...)
		return required, found
	}
	found = []string{fmt.Sprintf("Found configurations differ (%d)", len(founds))}
	for _, item := range founds {
		found = append(found, "  "+item.label)
		found = append(found, blockText(item.text, width, 4)...)
	}
	return required, found
}
func (m model) browseEvidence(g group, budget int) []string {
	required, found := m.evidenceParts(g, max(20, m.width-6))
	return packEvidence(required, found, budget)
}
func (m model) evidenceDocument(g group, width int) []string {
	required, found := m.evidenceParts(g, width)
	return append(required, found...)
}
