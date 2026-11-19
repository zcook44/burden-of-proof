package main

import (
	"os"
	"testing"

	"github.com/zcook44/checkmate/internal/checklist"
)

func TestSelectionStartsEmptyAndCanSelectMatchingStatus(t *testing.T) {
	root := t.TempDir()
	sample(t, root, "r1", "open")
	sample(t, root, "r2", "not_a_finding")
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(files)
	if m.selectedCount() != 0 {
		t.Fatal("hosts selected by default")
	}
	m = key(m, "f")
	m = key(m, "f") // status filter Open
	m = key(m, "m") // select matching status
	if m.selectedCount() != 1 || m.files[m.groups[0].matches[0].file].Rules[0].Status != "open" {
		t.Fatalf("matched selection wrong: %+v", m.groups[0].matches)
	}
	m = key(m, "A") // explicit select all
	if m.selectedCount() != 2 {
		t.Fatal("select all did not select both")
	}
	m = key(m, "c")
	if m.selectedCount() != 0 {
		t.Fatal("clear did not clear")
	}
}
func TestPreflightRefusesStaleLaterHostWithoutWritingEarlier(t *testing.T) {
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
	m = key(m, "1")
	m = key(m, "x")
	m = key(m, "enter")
	if err := os.WriteFile(p2, []byte(`{"changed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	m = key(m, "y")
	if m.stage != browse || m.message == "" {
		t.Fatalf("preflight not reported: %s", m.View())
	}
	b, _ := os.ReadFile(p1)
	if !containsAll(string(b), `"status":"open"`, `"comments":"old"`) {
		t.Fatalf("first host was modified: %s", b)
	}
}
