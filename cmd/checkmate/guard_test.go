package main

import (
	"os"
	"strings"
	"testing"

	"github.com/zcook44/checkmate/internal/checklist"
)

func TestBulkOpenToNotAFindingRequiresTypedOverride(t *testing.T) {
	root := t.TempDir()
	p1 := sample(t, root, "r1", "open")
	p2 := sample(t, root, "r2", "open")
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(files)
	m = key(m, "A")
	m = key(m, "e")
	m = key(m, "2")
	m = key(m, "x")
	m = key(m, "enter")
	if !strings.Contains(m.View(), "OPEN") || !strings.Contains(m.View(), "NOT A FINDING") || !strings.Contains(m.View(), "old") || !strings.Contains(m.View(), "x") {
		t.Fatal("preview lacks before/after details")
	}
	m = key(m, "y")
	if m.stage != guard {
		t.Fatalf("bulk downgrade was not guarded: %s", m.View())
	}
	for _, p := range []string{p1, p2} {
		b, _ := os.ReadFile(p)
		if !strings.Contains(string(b), `"status":"open"`) {
			t.Fatal("wrote before override")
		}
	}
	for _, r := range "OVERRIDE" {
		m = key(m, string(r))
	}
	m = key(m, "enter")
	if m.stage != browse {
		t.Fatal(m.View())
	}
	for _, p := range []string{p1, p2} {
		b, _ := os.ReadFile(p)
		if !strings.Contains(string(b), `"status": "not_a_finding"`) {
			t.Fatal("override did not apply")
		}
	}
}
