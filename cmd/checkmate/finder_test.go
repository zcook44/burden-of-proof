package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestFinderAcceptsHighlightedStigAndEscRestoresQuery(t *testing.T) {
	root := t.TempDir()
	hostCKLB(t, root, "switch1", "Cisco_IOS_STIG", "V-42")
	hostCKLB(t, root, "switch2", "Cisco_IOS_STIG", "V-99")
	files, err := loadChecklists(root, "")
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(files)
	m.query = "V-"
	m = key(m, "/")
	m = key(m, "9")
	if m.stage != search || !strings.Contains(m.View(), "STIG search") || !strings.Contains(m.View(), "> V-9_") {
		t.Fatal(m.View())
	}
	m = key(m, "enter")
	if m.stage != browse || m.groups[m.visible()[m.cursor]].sample.ID != "V-99" {
		t.Fatalf("finder did not land on V-99: %s", m.View())
	}
	m = key(m, "/")
	m = key(m, "x")
	m = viewKey(m, tea.KeyEsc)
	if m.stage != browse || m.query != "V-9" {
		t.Fatalf("esc kept %q", m.query)
	}
}

func TestHostFinderAndEscDoesNotQuit(t *testing.T) {
	root := t.TempDir()
	sample(t, root, "r1", "open")
	sample(t, root, "r2", "open")
	files, err := loadChecklists(root, "")
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(files)
	m.message = "Updated 1 checklist(s) in place"
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(model)
	if cmd != nil || m.message != "" || m.stage != browse {
		t.Fatal("esc quit or left the notice")
	}
	_, quit := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if quit == nil {
		t.Fatal("q did not quit")
	}
	root = t.TempDir()
	sample(t, root, "alpha", "open")
	sample(t, root, "beta", "open")
	files, err = loadChecklists(root, "")
	if err != nil {
		t.Fatal(err)
	}
	m = key(newModel(files), "h")
	if !strings.Contains(m.View(), "Host search") || !strings.Contains(m.View(), "> _") {
		t.Fatal(m.View())
	}
	m = viewKey(m, tea.KeyDown)
	m = key(m, "enter")
	g := m.groups[m.visible()[m.cursor]]
	ref := g.matches[m.hostIndices(g)[m.host]]
	if m.stage != browse || !strings.Contains(m.files[ref.file].Path, "beta") {
		t.Fatal(m.View())
	}
}
