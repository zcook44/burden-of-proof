package checklist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, dir, name, status string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	doc := map[string]any{"cklb_version": "1.0", "custom_root": "keep", "stigs": []any{map[string]any{"stig_id": "Cisco_IOS_STIG", "release_info": "V1R2", "rules": []any{map[string]any{"group_id": "V-42", "rule_id": "SV-42r1_rule", "rule_title": "Configure login policy", "severity": "high", "status": status, "comments": "original", "finding_details": "observed per device", "extra": "keep"}}}}}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiscoverNewestPerDirectory(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "device")
	old := fixture(t, d, "old.cklb", "open")
	newer := fixture(t, d, "new.cklb", "not_reviewed")
	now := time.Now()
	os.Chtimes(old, now.Add(-time.Hour), now.Add(-time.Hour))
	os.Chtimes(newer, now, now)
	files, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != newer || files[0].Rules[0].Status != "not_reviewed" {
		t.Fatalf("unexpected selection: %+v", files)
	}
}
func TestDiscoverRejectsTiedNewestAndSymlink(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "device")
	a := fixture(t, d, "a.cklb", "open")
	b := fixture(t, d, "b.cklb", "open")
	now := time.Now()
	os.Chtimes(a, now, now)
	os.Chtimes(b, now, now)
	if _, err := Discover(root); err == nil || !strings.Contains(err.Error(), "tie") {
		t.Fatalf("want tie error, got %v", err)
	}
	os.Remove(b)
	os.Symlink(a, b)
	if _, err := Discover(root); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestEditPreservesUnknownFieldsAndOnlySelectedRow(t *testing.T) {
	root := t.TempDir()
	p := fixture(t, filepath.Join(root, "device"), "one.cklb", "open")
	files, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Edit(files[0], 0, "not_a_finding", "Reviewed device configuration."); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["status"] != "not_a_finding" || row["comments"] != "Reviewed device configuration." || row["extra"] != "keep" || row["finding_details"] != "observed per device" || doc["custom_root"] != "keep" {
		t.Fatal(row)
	}
	stat, _ := os.Stat(p)
	if stat.Mode().Perm() != 0600 {
		t.Fatal(stat.Mode())
	}
}
func TestEditRejectsStaleFile(t *testing.T) {
	root := t.TempDir()
	p := fixture(t, root, "one.cklb", "open")
	files, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"changed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Edit(files[0], 0, "open", "note"); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("wanted stale error, got %v", err)
	}
}
func TestEditRejectsInvalidStatusOrEmptyComment(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "one.cklb", "open")
	files, _ := Discover(root)
	if err := Edit(files[0], 0, "resolved", "note"); err == nil {
		t.Fatal("bad status accepted")
	}
	if err := Edit(files[0], 0, "open", " "); err == nil {
		t.Fatal("empty comment accepted")
	}
}
