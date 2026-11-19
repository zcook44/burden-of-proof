package main

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/zcook44/checkmate/internal/checklist"
	"os"
	"strings"
	"testing"
)

func TestMultilineCommentPersistsAndRenders(t *testing.T) {
	root := t.TempDir()
	p := sample(t, root, "r1", "open")
	files, _ := checklist.Discover(root)
	m := newModel(files)
	m = key(m, "space")
	m = key(m, "e")
	m = key(m, "1")
	m = key(m, "first")
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlJ})
	m = next.(model)
	m = key(m, "second")
	if m.note != "first\nsecond" || !strings.Contains(m.View(), "second") {
		t.Fatal("multiline input failed")
	}
	m = key(m, "enter")
	m = key(m, "y")
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"comments": "first\nsecond"`) {
		t.Fatalf("multiline lost in CKLB: %s", b)
	}
}
