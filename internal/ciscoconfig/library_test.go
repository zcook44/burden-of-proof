package ciscoconfig

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPinnedChecksMatchTrackedSwitchBenchmarks(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	xeDir := filepath.Join(root, "examples", "cisco-synthetic", "targets", "ios-xe-switch-01")
	cfg, err := Parse(mustRead(t, filepath.Join(xeDir, "scan.running-config")))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := ParsePortRoles(mustRead(t, filepath.Join(xeDir, "port-roles.csv")))
	if err != nil {
		t.Fatal(err)
	}
	if unknown := UnknownInterfaces(cfg, roles); len(unknown) > 0 {
		t.Fatal(unknown)
	}
	benchmark := mustRead(t, filepath.Join(root, "stig-library-cisco", "U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml"))
	got := score(t, benchmark, cfg, roles)
	want := map[string]string{
		"V-220649": "open",
		"V-220650": "open",
		"V-220651": "open",
		"V-220655": "not_applicable",
		"V-220656": "not_a_finding",
		"V-220657": "not_a_finding",
		"V-220658": "open",
		"V-220659": "not_a_finding",
		"V-220660": "not_a_finding",
		"V-220661": "not_a_finding",
		"V-220662": "open",
		"V-220663": "not_a_finding",
		"V-220664": "not_a_finding",
		"V-220665": "not_applicable",
		"V-220666": "not_a_finding",
		"V-220667": "not_a_finding",
		"V-220668": "not_a_finding",
		"V-220669": "not_a_finding",
		"V-220670": "not_a_finding",
		"V-220671": "not_a_finding",
		"V-220672": "not_a_finding",
		"V-220673": "not_a_finding",
	}
	for id, status := range want {
		if got[id] != status {
			t.Errorf("%s got %s want %s", id, got[id], status)
		}
	}
	ndm := score(t, mustRead(t, filepath.Join(root, "stig-library-cisco", "U_Cisco_IOS-XE_Switch_NDM_STIG_V3R6_Manual-xccdf.xml")), cfg, roles)
	for id, status := range map[string]string{
		"V-220519": "not_a_finding",
		"V-220524": "open",
		"V-220531": "not_applicable",
		"V-220535": "open",
		"V-220537": "open",
		"V-220548": "not_a_finding",
		"V-220549": "not_a_finding",
		"V-220554": "open",
		"V-220556": "open",
		"V-220560": "not_a_finding",
		"V-220568": "not_a_finding",
	} {
		if ndm[id] != status {
			t.Errorf("NDM %s got %s want %s", id, ndm[id], status)
		}
	}
}

func TestNXOSAdminSessionLoggingIsClosedWhenAuthprivLevelIsPresent(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	cfg, err := Parse(mustRead(t, filepath.Join(root, "examples", "cisco-synthetic", "targets", "nx-access-01", "scan.running-config")))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := ParsePortRoles(mustRead(t, filepath.Join(root, "examples", "cisco-synthetic", "targets", "nx-access-01", "port-roles.csv")))
	if err != nil {
		t.Fatal(err)
	}
	got := score(t, mustRead(t, filepath.Join(root, "stig-library-cisco", "U_Cisco_NX-OS_Switch_NDM_STIG_V3R6_Manual-xccdf.xml")), cfg, roles)
	if got["V-220510"] != "not_a_finding" {
		t.Fatalf("session start/end logging: got %s", got["V-220510"])
	}
	if got["V-220508"] != "not_a_finding" {
		t.Fatalf("logon auditing: got %s", got["V-220508"])
	}
	for _, id := range []string{"V-220475", "V-220480", "V-220487", "V-220488", "V-220489", "V-220497", "V-220503", "V-220504", "V-220512", "V-220516"} {
		if got[id] != "not_a_finding" {
			t.Errorf("%s got %s, want not_a_finding", id, got[id])
		}
	}
	bare, err := Parse([]byte("version 9.3(10)\nhostname nx\nlogging level authpriv 4\n"))
	if err != nil {
		t.Fatal(err)
	}
	status, _, _ := Evaluate(bare, RoleTable{}, "Cisco_NX-OS_Switch_NDM_STIG", "V-220510", "SV-220510r961830_rule", "CISC-ND-001280", "The Cisco switch must generate audit records showing starting and ending time for administrator access to the system.", "logging level authpri 6\nIf the switch is not configured to generate log records showing starting and ending time for administrator access, this is a finding.")
	if status != "open" {
		t.Fatalf("level 4 should be open, got %s", status)
	}
	renamed, err := Parse([]byte("version 9.3(10)\nhostname nx\naaa accounting default group AUDIT_GRP\nradius-server host 198.51.100.10 key 0 placeholder\nradius-server host 198.51.100.11 key 0 placeholder\n"))
	if err != nil {
		t.Fatal(err)
	}
	status, _, comment := Evaluate(renamed, RoleTable{}, "Cisco_NX-OS_Switch_NDM_STIG", "V-220475", "SV-220475r960777_rule", "CISC-ND-000090", "The Cisco switch must be configured to automatically audit account creation.", "aaa accounting default group RADIUS_SERVERS\nserver 10.1.48.10\nIf account creation is not automatically audited, this is a finding.")
	if status != "not_a_finding" || strings.Contains(comment, "10.1.48.10") {
		t.Fatalf("different group name and addresses: %s %s", status, comment)
	}
	if !exampleTokenIsPlaceholder("10.1.48.10") || !exampleTokenIsPlaceholder("RADIUS_SERVERS") || exampleTokenIsPlaceholder("accounting") {
		t.Fatal("placeholder detection mismatch")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func score(t *testing.T, benchmark []byte, cfg *Config, roles RoleTable) map[string]string {
	t.Helper()
	var doc struct {
		XMLName xml.Name `xml:"Benchmark"`
		ID      string   `xml:"id,attr"`
		Groups  []struct {
			ID    string `xml:"id,attr"`
			Rules []struct {
				ID      string `xml:"id,attr"`
				Title   string `xml:"title"`
				Version string `xml:"version"`
				Check   struct {
					Content string `xml:"check-content"`
				} `xml:"check"`
			} `xml:"Rule"`
		} `xml:"Group"`
	}
	if err := xml.Unmarshal(benchmark, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, group := range doc.Groups {
		if len(group.Rules) != 1 {
			t.Fatalf("%s rules", group.ID)
		}
		rule := group.Rules[0]
		status, _, _ := Evaluate(cfg, roles, doc.ID, group.ID, rule.ID, rule.Version, rule.Title, rule.Check.Content)
		if status == "" {
			status = "not_reviewed"
		}
		out[group.ID] = status
	}
	return out
}
