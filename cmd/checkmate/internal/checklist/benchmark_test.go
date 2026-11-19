package checklist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCKLB(t *testing.T, dir, name string, stigs []any) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	doc := map[string]any{"cklb_version": "1.0", "stigs": stigs}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func stig(id, group, status string) map[string]any {
	return map[string]any{
		"stig_id": id, "release_info": "V1R2",
		"rules": []any{map[string]any{
			"group_id": group, "rule_id": group + "r1_rule", "rule_title": id + " " + group,
			"severity": "high", "status": status, "comments": "original", "finding_details": id,
		}},
	}
}

func TestDiscoverBenchmarkKeepsOlderFileWhenNewerIsAnotherBenchmark(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "switch1")
	cisco := writeCKLB(t, d, "ios.cklb", []any{stig("Cisco_IOS_STIG", "V-42", "open")})
	rhel := writeCKLB(t, d, "rhel.cklb", []any{stig("RHEL_9_STIG", "V-230228", "not_reviewed")})
	now := time.Now()
	os.Chtimes(cisco, now.Add(-time.Hour), now.Add(-time.Hour))
	os.Chtimes(rhel, now, now)

	all, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Path != rhel || all[0].Rules[0].Benchmark != "RHEL_9_STIG" {
		t.Fatalf("unnamed discovery = %+v", all)
	}
	named, err := DiscoverBenchmark(root, " Cisco_IOS_STIG ")
	if err != nil {
		t.Fatal(err)
	}
	if len(named) != 1 || named[0].Path != cisco || len(named[0].Rules) != 1 || named[0].Rules[0].ID != "V-42" {
		t.Fatalf("named discovery = %+v", named)
	}
}

func TestDiscoverBenchmarkDropsOtherStigsInTheChosenFile(t *testing.T) {
	root := t.TempDir()
	p := writeCKLB(t, filepath.Join(root, "host"), "both.cklb", []any{
		stig("Cisco_IOS_STIG", "V-42", "open"),
		stig("RHEL_9_STIG", "V-230228", "not_reviewed"),
	})
	files, err := DiscoverBenchmark(root, "Cisco_IOS_STIG")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || len(files[0].Rules) != 1 || files[0].Rules[0].Benchmark != "Cisco_IOS_STIG" {
		t.Fatalf("%+v", files)
	}
	if err := Edit(files[0], 0, "not_a_finding", "reviewed cisco"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	rows := doc["stigs"].([]any)
	cisco := rows[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	rhel := rows[1].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if cisco["status"] != "not_a_finding" || cisco["comments"] != "reviewed cisco" || rhel["status"] != "not_reviewed" {
		t.Fatalf("cisco %+v rhel %+v", cisco, rhel)
	}
}

func TestDiscoverBenchmarkReportsPresentIDsAndIgnoresUnrelatedTie(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "host")
	writeCKLB(t, d, "rhel.cklb", []any{stig("RHEL_9_STIG", "V-230228", "open")})
	if _, err := DiscoverBenchmark(root, "Cisco_IOS_STIG"); err == nil || !strings.Contains(err.Error(), "Cisco_IOS_STIG") || !strings.Contains(err.Error(), "RHEL_9_STIG") {
		t.Fatal(err)
	}
	a := writeCKLB(t, d, "a.cklb", []any{stig("Cisco_IOS_STIG", "V-42", "open")})
	b := writeCKLB(t, d, "b.cklb", []any{stig("RHEL_9_STIG", "V-230228", "open")})
	now := time.Now()
	os.Chtimes(a, now, now)
	os.Chtimes(b, now, now)
	files, err := DiscoverBenchmark(root, "Cisco_IOS_STIG")
	if err != nil || len(files) != 1 || files[0].Path != a {
		t.Fatalf("unrelated tie rejected the match: %v %+v", err, files)
	}
	c := writeCKLB(t, d, "c.cklb", []any{stig("Cisco_IOS_STIG", "V-42", "open")})
	os.Chtimes(c, now, now)
	if _, err := DiscoverBenchmark(root, "Cisco_IOS_STIG"); err == nil || !strings.Contains(err.Error(), "tie") {
		t.Fatal(err)
	}
}
