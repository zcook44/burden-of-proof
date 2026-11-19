package main

import (
	"github.com/zcook44/checkmate/internal/checklist"
	"strings"
	"testing"
)

func TestFullPerHostPreviewAndEmptySelectionGate(t *testing.T) {
	root := t.TempDir()
	sample(t, root, "r1", "open")
	files, _ := checklist.Discover(root)
	m := newModel(files)
	m = key(m, "e")
	if m.stage != browse || !strings.Contains(m.View(), "Select at least one") {
		t.Fatal("empty selection was not gated")
	}
	m = key(m, "space")
	m = key(m, "e")
	m = key(m, "1")
	for _, r := range "new evidence" {
		m = key(m, string(r))
	}
	m = key(m, "enter")
	m = key(m, "v")
	if m.stage != preview || !containsAll(m.View(), "Old comment", "old", "New comment", "new evidence", "OPEN") {
		t.Fatal(m.View())
	}
	m = key(m, "esc")
	if m.stage != confirm {
		t.Fatal("preview did not return to confirmation")
	}
}
