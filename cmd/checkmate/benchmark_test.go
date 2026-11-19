package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hostCKLB(t *testing.T, root, host, stig, group string) {
	t.Helper()
	dir := filepath.Join(root, host)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body := `{"title":"synthetic.cklb","cklb_version":"1.0","stigs":[{"stig_id":"` + stig + `","release_info":"V1R2","rules":[{"group_id":"` + group + `","rule_id":"` + group + `r1_rule","rule_title":"` + stig + ` rule","severity":"high","status":"open","comments":"old","finding_details":"host data"}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "scan.cklb"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestNamedBenchmarkOpensOnlyThatChecklist(t *testing.T) {
	root := t.TempDir()
	hostCKLB(t, root, "switch1", "Cisco_IOS_STIG", "V-42")
	hostCKLB(t, root, "node1", "RHEL_9_STIG", "V-230228")
	all, err := loadChecklists(root, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("open all: %v (%d files)", err, len(all))
	}
	named, err := loadChecklists(root, "Cisco_IOS_STIG")
	if err != nil || len(named) != 1 || named[0].Rules[0].Benchmark != "Cisco_IOS_STIG" {
		t.Fatalf("named: %v %+v", err, named)
	}
	m := newModel(named)
	m.benchmark = "Cisco_IOS_STIG"
	if !strings.Contains(m.View(), "Benchmark: Cisco_IOS_STIG") || strings.Contains(m.View(), "V-230228") {
		t.Fatal(m.View())
	}
	if _, err := loadChecklists(root, "RHEL_8_STIG"); err == nil || !strings.Contains(err.Error(), "RHEL_9_STIG") || !strings.Contains(err.Error(), "Cisco_IOS_STIG") {
		t.Fatal(err)
	}
}

func TestUnnamedDiscoveryHeaderStaysUnscoped(t *testing.T) {
	root := t.TempDir()
	hostCKLB(t, root, "switch1", "Cisco_IOS_STIG", "V-42")
	files, err := loadChecklists(root, "  ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(newModel(files).View(), "Benchmark:") {
		t.Fatal("unnamed session announced a benchmark")
	}
}
