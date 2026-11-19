package main

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zcook44/checkmate/internal/checklist"
)

func writeRule(t *testing.T, dir, host, status, check, finding string) {
	t.Helper()
	d := filepath.Join(dir, host)
	if err := os.MkdirAll(d, 0700); err != nil {
		t.Fatal(err)
	}
	body := `{"title":"synthetic.cklb","id":"123e4567-e89b-12d3-a456-426614174000","cklb_version":"1.0","stigs":[{"stig_name":"Cisco IOS STIG","display_name":"Cisco IOS","stig_id":"Cisco_IOS_STIG","release_info":"V1R2","uuid":"123e4567-e89b-12d3-a456-426614174001","size":1,"rules":[{"group_id":"V-42","rule_id":"SV-42r1_rule","rule_title":"Configure login policy","severity":"high","status":"` + status + `","comments":"old","check_content":"` + check + `","finding_details":"` + finding + `"}]}]}`
	if err := os.WriteFile(filepath.Join(d, "scan.cklb"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestBrowseShowsRequiredCheckAndDistinctFindings(t *testing.T) {
	root := t.TempDir()
	check := `Verify failed logins are blocked.\nRequired configuration:\nlogin block-for 300 attempts 3 within 60`
	writeRule(t, root, "sw1", "open", check, `interface Vlan1\n ip address 192.0.2.3 255.255.255.0`)
	writeRule(t, root, "sw2", "open", check, `interface Vlan1\n shutdown`)
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if files[0].Rules[0].Check == "" {
		t.Fatal("check text was not loaded")
	}
	m := key(newModel(files), "A")
	view := m.View()
	if !containsAll(view, "Required check", "login block-for 300 attempts 3 within 60", "Found configurations differ (2)", "sw1", "sw2", "192.0.2.3", "shutdown") {
		t.Fatal(view)
	}
	if containsAll(view, "ip address 192.0.2.3") && containsAll(view, "interface Vlan1 ip address") {
		t.Fatal("finding lines were flattened: " + view)
	}
	m = key(m, "v")
	if !containsAll(m.View(), "Check and findings", "login block-for 300", "192.0.2.3", "shutdown", "Comment") {
		t.Fatal(m.View())
	}
	browse := key(m, "esc")
	fitted, _ := browse.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	if got := lipgloss.Height(fitted.(model).View()); got > 24 {
		t.Fatalf("browse overflowed height: %d\n%s", got, fitted.(model).View())
	}
}

func TestIdenticalFindingsStayOneBlock(t *testing.T) {
	root := t.TempDir()
	writeRule(t, root, "sw1", "open", "login block-for 300 attempts 3 within 60", "login block-for 300 attempts 3 within 60")
	writeRule(t, root, "sw2", "open", "login block-for 300 attempts 3 within 60", "login block-for 300 attempts 3 within 60")
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	view := key(newModel(files), "A").View()
	if !containsAll(view, "Found on sw1, sw2", "login block-for 300") || containsAll(view, "Found configurations differ") {
		t.Fatal(view)
	}
}
