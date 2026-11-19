package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zcook44/checkmate/internal/checklist"
)

func sample(t *testing.T, dir, host, status string) string {
	t.Helper()
	d := filepath.Join(dir, host)
	if err := os.MkdirAll(d, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "scan.cklb")
	b := `{"title":"synthetic.cklb","id":"123e4567-e89b-12d3-a456-426614174000","cklb_version":"1.0","stigs":[{"stig_name":"Cisco IOS STIG","display_name":"Cisco IOS","stig_id":"Cisco_IOS_STIG","release_info":"V1R2","uuid":"123e4567-e89b-12d3-a456-426614174001","size":1,"rules":[{"group_id":"V-42","rule_id":"SV-42r1_rule","rule_title":"Configure login policy","severity":"high","status":"` + status + `","comments":"old","finding_details":"host data"}]}]}`
	if err := os.WriteFile(p, []byte(b), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func key(m model, k string) model {
	var msg tea.KeyMsg
	if k == "enter" {
		msg.Type = tea.KeyEnter
	} else if k == "space" {
		msg.Type = tea.KeySpace
	} else {
		msg.Type = tea.KeyRunes
		msg.Runes = []rune(k)
	}
	next, _ := m.Update(msg)
	return next.(model)
}
func TestTUIListsAllStatusesAndGroupsHosts(t *testing.T) {
	root := t.TempDir()
	sample(t, root, "r1", "not_a_finding")
	sample(t, root, "r2", "open")
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(files)
	if len(m.groups) != 1 || len(m.groups[0].matches) != 2 {
		t.Fatalf("grouping: %+v", m.groups)
	}
	if got := m.View(); !containsAll(got, "Cisco_IOS_STIG", "V-42", "HIGH", "Configure login policy", "r1", "r2") {
		t.Fatal(got)
	}
}
func TestTUICommentAcceptsSpaces(t *testing.T) {
	root := t.TempDir()
	sample(t, root, "r1", "open")
	files, _ := checklist.Discover(root)
	m := key(key(key(newModel(files), "space"), "e"), "2")
	for _, k := range []string{"a", "space", "b"} {
		m = key(m, k)
	}
	if m.note != "a b" {
		t.Fatalf("comment lost spaces: %q", m.note)
	}
}
func TestTUIShowsFullFindingDetails(t *testing.T) {
	root := t.TempDir()
	sample(t, root, "switch1", "open")
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	m := key(newModel(files), "v")
	if !containsAll(m.View(), "Check and findings", "Required check", "Found on", "host data") {
		t.Fatal(m.View())
	}
}
func TestTUIEditsOnlySelectedHostAfterConfirmation(t *testing.T) {
	root := t.TempDir()
	p1 := sample(t, root, "r1", "open")
	p2 := sample(t, root, "r2", "open")
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(files)
	m = key(m, "tab")   // focus second host
	m = key(m, "space") // select only second host
	m = key(m, "e")
	m = key(m, "n")     // edit, choose Not a Finding
	m = key(m, "enter") // comment field
	for _, r := range "Verified device configuration" {
		m = key(m, string(r))
	}
	m = key(m, "enter") // confirmation
	if m.stage != confirm {
		t.Fatalf("not confirming: %s", m.View())
	}
	m = key(m, "y")
	if m.stage != browse || m.selectedCount() != 0 || !strings.Contains(m.message, "Updated") {
		t.Fatalf("did not return to browse: %s", m.View())
	}
	m = key(m, "j")
	if m.message != "" {
		t.Fatalf("notice stayed after moving: %s", m.message)
	}
	one, _ := os.ReadFile(p1)
	two, _ := os.ReadFile(p2)
	if !containsAll(string(one), `"status":"open"`) || !containsAll(string(two), `"status": "not_a_finding"`, `"comments": "Verified device configuration"`) {
		t.Fatalf("unexpected updates: %s / %s", one, two)
	}
}
func containsAll(s string, terms ...string) bool {
	for _, term := range terms {
		if !strings.Contains(s, term) {
			return false
		}
	}
	return true
}
