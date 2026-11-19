package main

import (
	"os"
	"strings"
	"testing"

	"github.com/zcook44/checkmate/internal/checklist"
)

func TestHostSearchLimitsDisplayedHostsAndSelectionScope(t *testing.T) {
	root := t.TempDir()
	sample(t, root, "r1", "open")
	sample(t, root, "r2", "open")
	files, _ := checklist.Discover(root)
	m := newModel(files)
	m = key(m, "h")
	for _, r := range "r2" {
		m = key(m, string(r))
	}
	m = key(m, "enter")
	if len(m.visible()) != 1 || !strings.Contains(m.View(), "r2") || strings.Contains(m.View(), "r1/scan.cklb") || !strings.Contains(m.View(), "1 hidden by host search") {
		t.Fatal(m.View())
	}
	m = key(m, "A")
	if m.selectedCount() != 2 {
		t.Fatal("select all left a host on this rule unselected")
	}
	m = key(m, "c")
	if m.selectedCount() != 0 {
		t.Fatal("deselect all left a host selected")
	}
}
func TestStatusAndHostSearchIntersect(t *testing.T) {
	root := t.TempDir()
	sample(t, root, "r1", "open")
	sample(t, root, "r2", "not_reviewed")
	files, _ := checklist.Discover(root)
	m := newModel(files)
	m = key(m, "h")
	for _, r := range "r1" {
		m = key(m, string(r))
	}
	m = key(m, "enter")
	m = key(m, "f")
	if len(m.visible()) != 0 {
		t.Fatal("status matched hidden host rather than visible host")
	}
}
func TestSeverityFilterCyclesGroupSeverities(t *testing.T) {
	root := t.TempDir()
	sample(t, root, "high", "open")
	p := sample(t, root, "low", "open")
	b, _ := os.ReadFile(p)
	s := strings.ReplaceAll(string(b), `"V-42"`, `"V-43"`)
	s = strings.ReplaceAll(s, `"SV-42r1_rule"`, `"SV-43r1_rule"`)
	s = strings.ReplaceAll(s, `"severity":"high"`, `"severity":"low"`)
	os.WriteFile(p, []byte(s), 0600)
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(files)
	if len(m.visible()) != 2 {
		t.Fatal("fixture did not have two groups")
	}
	m = key(m, "F")
	if len(m.visible()) != 1 || m.groups[m.visible()[0]].sample.Severity != "high" {
		t.Fatal("high filter failed")
	}
	m = key(m, "F")
	if len(m.visible()) != 0 {
		t.Fatal("medium filter failed")
	}
	m = key(m, "F")
	if len(m.visible()) != 1 || m.groups[m.visible()[0]].sample.Severity != "low" {
		t.Fatal("low filter failed")
	}
}
