package draft

import (
	"strings"
	"testing"
)

// Synthetic fixture mirrors only official IDs, revision, and the two check criteria;
// it does not redistribute benchmark XML or device secrets.
const iosXEL2SFixture = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Cisco_IOS_XE_Switch_L2S_STIG"><title>IOS-XE Switch L2S</title><version>3</version><plain-text id="release-info">Release: 2</plain-text><Group id="V-220657"><Rule id="SV-220657r856279_rule" severity="medium"><title>The Cisco switch must have STP Loop Guard enabled.</title><version>CISC-L2-000110</version><check><check-content>Review the switch configuration to verify that STP Loop Guard is enabled: spanning-tree loopguard default. If STP Loop Guard is not enabled, this is a finding.</check-content></check></Rule></Group><Group id="V-220664"><Rule id="SV-220664r539671_rule" severity="medium"><title>The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links.</title><version>CISC-L2-000180</version><check><check-content>If STP is required, review the switch configuration for spanning-tree mode rapid-pvst. Multiple STP (MSTP) can be configured as an alternate mode. If either RSTP or MSTP has not been implemented where STP is required, this is a finding.</check-content></check></Rule></Group><Group id="V-220666"><Rule id="SV-220666r539671_rule" severity="medium"><title>The Cisco switch must have all trunk links enabled statically.</title><version>CISC-L2-000200</version><check><check-content>Review show interfaces switchport; if trunk negotiation is enabled on any interface, this is a finding.</check-content></check></Rule></Group></Benchmark>`

func TestCiscoConfigEvaluatesDecidableSTPButNotOperationalTrunk(t *testing.T) {
	config := []byte("hostname DOD-ACC-SW01\nspanning-tree mode rapid-pvst\nspanning-tree loopguard default\nusername fake secret 9 SENSITIVE_TEST_MARKER\ninterface GigabitEthernet1/0/1\n switchport mode trunk\n switchport nonegotiate\n")
	doc, err := BuildCiscoConfig(config, "DOD-ACC-SW01", []byte(iosXEL2SFixture))
	if err != nil {
		t.Fatal(err)
	}
	rows := ciscoRules(t, doc)
	for i, status := range []string{"not_a_finding", "not_a_finding", "not_reviewed"} {
		row := rows[i].(map[string]any)
		if row["status"] != status {
			t.Fatalf("rule %v: got %v, want %s", row["group_id"], row["status"], status)
		}
		for _, field := range []string{"comments", "finding_details"} {
			text := row[field].(string)
			if text == "" || strings.Contains(text, "SENSITIVE_TEST_MARKER") {
				t.Errorf("rule %v unsafe %s: %q", row["group_id"], field, text)
			}
			if i < 2 && !strings.Contains(strings.ToLower(text), "automated") {
				t.Errorf("rule %v lacks method in %s: %q", row["group_id"], field, text)
			}
		}
	}
	if !strings.Contains(doc["title"].(string), "AUTO") {
		t.Fatal("auto-evaluated checklist still claims all rules are unreviewed")
	}
}

func TestCiscoConfigDoesNotReadBannerTextAsCommands(t *testing.T) {
	config := []byte("hostname switch1\nbanner motd ^C\nspanning-tree mode rapid-pvst\nspanning-tree loopguard default\n^C\n")
	doc, err := BuildCiscoConfig(config, "switch1", []byte(iosXEL2SFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range ciscoRules(t, doc)[:2] {
		if row := v.(map[string]any); row["status"] != "not_reviewed" {
			t.Fatalf("banner text was mistaken for a configuration command: %v", row["group_id"])
		}
	}
}

func TestCiscoConfigRejectsChangedCheckSemantics(t *testing.T) {
	changed := strings.Replace(iosXEL2SFixture, "If STP Loop Guard is not enabled, this is a finding.", "If STP Loop Guard is not enabled, this is NOT a finding.", 1)
	doc, err := BuildCiscoConfig([]byte("spanning-tree loopguard default\nspanning-tree mode rapid-pvst\n"), "switch1", []byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	if got := ciscoRules(t, doc)[0].(map[string]any)["status"]; got != "not_reviewed" {
		t.Fatalf("changed check semantics auto-approved: %v", got)
	}
}

func TestCiscoConfigExplicitlyDisabledLoopGuardIsOpen(t *testing.T) {
	config := []byte("hostname switch1\nspanning-tree mode rapid-pvst\nno spanning-tree loopguard default\n")
	doc, err := BuildCiscoConfig(config, "switch1", []byte(iosXEL2SFixture))
	if err != nil {
		t.Fatal(err)
	}
	row := ciscoRules(t, doc)[0].(map[string]any)
	if row["status"] != "open" || !strings.Contains(row["finding_details"].(string), "explicitly disabled") || !strings.Contains(row["comments"].(string), "Finding") {
		t.Fatalf("explicitly disabled guard not identified: %+v", row)
	}
}
