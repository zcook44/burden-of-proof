package checklist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoverAllowsOlderTimestampTie(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "device")
	a := fixture(t, d, "a.cklb", "open")
	b := fixture(t, d, "b.cklb", "open")
	c := fixture(t, d, "c.cklb", "open")
	now := time.Now()
	for _, p := range []string{a, b} {
		os.Chtimes(p, now.Add(-time.Hour), now.Add(-time.Hour))
	}
	os.Chtimes(c, now, now)
	files, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != c {
		t.Fatalf("unexpected: %+v", files)
	}
}
func TestDiscoverRejectsDuplicateControlWithinOneChecklist(t *testing.T) {
	root := t.TempDir()
	p := fixture(t, root, "one.cklb", "open")
	b, _ := os.ReadFile(p)
	s := string(b)
	start := strings.Index(s, `{"comments":"original"`)
	end := strings.Index(s[start:], "}") + start + 1
	if start < 0 || end <= start {
		t.Fatal("bad fixture")
	}
	row := s[start:end]
	s = strings.Replace(s, `"rules":[`+row+`]`, `"rules":[`+row+`,`+row+`]`, 1)
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
}
