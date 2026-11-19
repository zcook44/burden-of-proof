package draft

import (
	"strings"
	"testing"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

func TestViewerSentence(t *testing.T) {
	got := sentenceFromBrief("Path=/etc/ssh/sshd_config; Content=PermitRootLogin no")
	if got != "This host's /etc/ssh/sshd_config has PermitRootLogin no." {
		t.Fatalf("sentence: %q", got)
	}
	comment := rhelComment("not_a_finding", true, "all mapped sources passed", "pass", "Path=/etc/ssh/sshd_config; Content=PermitRootLogin no")
	want := "Not a Finding. This host's /etc/ssh/sshd_config has PermitRootLogin no. The SSG check passed; this is that result placed on the DISA rule id."
	if comment != want {
		t.Fatalf("comment: %q", comment)
	}
}

func TestViewerManualText(t *testing.T) {
	desc := "&lt;VulnDiscussion&gt;Root login lets an attacker own the host.&lt;/VulnDiscussion&gt;&lt;PotentialImpacts&gt;Disabling root login can break an existing break-glass account.&lt;/PotentialImpacts&gt;"
	bench := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG"><title>RHEL 9 STIG</title><version>2</version><Group id="V-100"><title>Group title</title><Rule id="SV-100r2_rule" severity="high"><title>Rule title</title><version>RHEL-09-111111</version><description>` + desc + `</description><fixtext>Disable root SSH login.</fixtext><check><check-content>Check PermitRootLogin.</check-content></check></Rule></Group></Benchmark>`
	report, err := reconcile.Convert([]byte(scan), []byte(bench))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := BuildMapped(report, []byte(bench))
	if err != nil {
		t.Fatal(err)
	}
	if doc["title"] != "node.example.test - RHEL 9 STIG" {
		t.Fatalf("title: %v", doc["title"])
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["discussion"] != "Root login lets an attacker own the host." || row["potential_impacts"] != "Disabling root login can break an existing break-glass account." || row["fix_text"] != "Disable root SSH login." || row["check_content"] != "Check PermitRootLogin." {
		t.Fatalf("manual fields: %#v", row)
	}
	if strings.Contains(row["finding_details"].(string), "SHA-256") || strings.Contains(row["comments"].(string), "SHA-256") {
		t.Fatalf("hash leaked into checklist text: %#v", row)
	}
}
