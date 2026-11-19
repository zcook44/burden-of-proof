package main

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zcook44/checkmate/internal/checklist"
)

func viewKey(m model, typ tea.KeyType) model {
	next, _ := m.Update(tea.KeyMsg{Type: typ})
	return next.(model)
}
func manyHosts(t *testing.T, n int) model {
	t.Helper()
	root := t.TempDir()
	for i := 0; i < n; i++ {
		sample(t, root, fmt.Sprintf("host-%02d", i), "open")
	}
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := newModel(files).Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	return next.(model)
}
func TestHostListPagesWithoutOverflowAndSelectionPersists(t *testing.T) {
	m := manyHosts(t, 55)
	first := m.View()
	if lipgloss.Height(first) > 24 {
		t.Fatalf("view overflowed terminal: %d lines", lipgloss.Height(first))
	}
	if !strings.Contains(first, "host-00") || strings.Contains(first, "host-54") {
		t.Fatal("host viewport not bounded")
	}
	m = key(m, "space") // select host 00
	m = viewKey(m, tea.KeyPgDown)
	if m.host == 0 || !strings.Contains(m.View(), fmt.Sprintf("host-%02d", m.host)) {
		t.Fatalf("page did not advance: %d", m.host)
	}
	m = viewKey(m, tea.KeyEnd)
	if m.host != 54 || !strings.Contains(m.View(), "host-54") {
		t.Fatalf("last host unreachable: %d", m.host)
	}
	m = viewKey(m, tea.KeyHome)
	if !m.groups[0].matches[0].selected || !strings.Contains(m.View(), "host-00") {
		t.Fatal("selection was lost across pages")
	}
}
func TestConfirmationPagesSelectedHosts(t *testing.T) {
	m := manyHosts(t, 55)
	m = key(m, "A")
	m = key(m, "e")
	m = key(m, "2")
	m = key(m, "x")
	m = key(m, "enter")
	view := m.View()
	if m.stage != confirm || !strings.Contains(view, "55 selected") || !strings.Contains(view, "Confirm this change") || !strings.Contains(view, "Was  Open 55") || !strings.Contains(view, "Y apply") || !strings.Contains(view, "╔") || lipgloss.Height(view) > 24 {
		t.Fatal(view)
	}
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > 80 {
			t.Fatalf("confirmation overflowed width: %d\n%s", lipgloss.Width(line), view)
		}
	}
	m = viewKey(m, tea.KeyEnd)
	if !strings.Contains(m.View(), "host-54") || lipgloss.Height(m.View()) > 24 {
		t.Fatal(m.View())
	}
}
func TestStatusPaletteMatchesSTIGViewerSemantics(t *testing.T) {
	for status, color := range map[string]string{"open": "red", "not_a_finding": "green", "not_applicable": "black", "not_reviewed": "gray"} {
		if got := statusColor(status); got != color {
			t.Errorf("%s color = %s, want %s", status, got, color)
		}
	}
}
