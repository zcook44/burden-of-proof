package draft

import (
	"strings"
	"testing"
	"time"

	"github.com/zcook44/burden-of-proof/internal/ciscoconfig"
	"github.com/zcook44/burden-of-proof/internal/netxccdf"
)

func TestNetworkXCCDFRoundTripKeepsScannerResult(t *testing.T) {
	config := []byte("version 17.9\nhostname sw1\nspanning-tree loopguard default\nend\n")
	doc, err := BuildCiscoReview(config, "sw1", []byte(iosXEL2SFixture), ciscoconfig.RoleTable{})
	if err != nil {
		t.Fatal(err)
	}
	id := netxccdf.Identity{HostName: "sw1", FQDN: "sw1.example.test", IPAddress: "192.0.2.10", MACAddress: "0200.0000.0010", Role: "Access switch", TargetType: "Cisco IOS-XE switch"}
	raw, err := netxccdf.FromChecklist(id, "Cisco_IOS_XE_Switch_L2S_STIG", netxccdf.ResultMeta{ConfigSHA256: strings.Repeat("ab", 32), ConfigComplete: true}, doc, time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "<result>pass</result>") || !strings.Contains(string(raw), "rule-result") || !strings.Contains(string(raw), "TestResult") || !strings.Contains(string(raw), "<target>sw1</target>") || !strings.Contains(string(raw), "<target-address>192.0.2.10</target-address>") || !strings.Contains(string(raw), "sw1.example.test") || !strings.Contains(string(raw), "02:00:00:00:00:10") {
		t.Fatalf("result does not resemble an oscap XCCDF results file:\n%s", raw)
	}
	scan, err := netxccdf.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := BuildFromNetworkScan([]byte(iosXEL2SFixture), scan)
	if err != nil {
		t.Fatal(err)
	}
	original := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)
	converted := again["stigs"].([]any)[0].(map[string]any)["rules"].([]any)
	if len(original) != len(converted) {
		t.Fatalf("rule count %d", len(converted))
	}
	for i := range original {
		if original[i].(map[string]any)["status"] != converted[i].(map[string]any)["status"] {
			t.Fatalf("status drifted for %s", original[i].(map[string]any)["group_id"])
		}
	}
	if !scan.ConfigComplete || scan.ConfigSHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("scan evidence: %#v", scan)
	}
	if !strings.Contains(converted[0].(map[string]any)["finding_details"].(string), "Network XCCDF result: pass") {
		t.Fatal("checklist was not built from the scan result")
	}
	target := again["target_data"].(map[string]any)
	if target["host_name"] != "sw1" || target["fqdn"] != "sw1.example.test" || target["ip_address"] != "192.0.2.10" || target["mac_address"] != "02:00:00:00:00:10" || target["role"] != "Access switch" || target["technology_area"] != "Network" || target["is_web_database"] != false {
		t.Fatalf("checklist target data: %#v", target)
	}
}
