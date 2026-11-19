package tailoring

import (
	"strings"
	"testing"
)

func controls() map[string]string {
	return map[string]string{
		"V-100": "SV-100r1_rule",
		"V-200": "SV-200r1_rule",
	}
}

func TestParseRootPinAndHostInherits(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	root := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: " + hash + "\nrules:\n  - stig_id: V-100\n    sv_id: SV-100r1_rule\n    status: not_a_finding\n    comment: site default\n"
	rf, err := Parse([]byte(root), Root, "root.yaml", "RHEL_9_STIG", hash, controls())
	if err != nil || len(rf.Rules) != 1 {
		t.Fatalf("root: %v %+v", err, rf)
	}
	host := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nrules:\n  - stig_id: V-100\n    sv_id: SV-100r1_rule\n    status: auto\n    comment: this host keeps the scan\n"
	hf, err := Parse([]byte(host), Host, "host.yaml", "RHEL_9_STIG", hash, controls())
	if err != nil {
		t.Fatal(err)
	}
	if hf.BenchmarkSHA256 != "" {
		t.Fatal("host stored a pin")
	}
	withPin := strings.Replace(host, "benchmark_id: RHEL_9_STIG\n", "benchmark_id: RHEL_9_STIG\nbenchmark_sha256: "+hash+"\n", 1)
	if _, err := Parse([]byte(withPin), Host, "host.yaml", "RHEL_9_STIG", hash, controls()); err == nil || !strings.Contains(err.Error(), "root tailoring file") {
		t.Fatalf("host pin accepted: %v", err)
	}
	stale := strings.Replace(root, hash, strings.Repeat("0", 64), 1)
	if _, err := Parse([]byte(stale), Root, "root.yaml", "RHEL_9_STIG", hash, controls()); err == nil || !strings.Contains(err.Error(), "rehash") {
		t.Fatalf("stale root pin accepted: %v", err)
	}
	merged := Merge(rf.Rules, hf.Rules)
	if len(merged) != 1 || merged[0].Origin != "host" || merged[0].Status != "auto" {
		t.Fatalf("merge: %+v", merged)
	}
}

func TestParseRejectsLegacySchema(t *testing.T) {
	body := "rules:\n  - stig_id: V-100\n    sv_id: SV-100r1_rule\n    status: open\n    comment: old\n"
	_, err := Parse([]byte(body), Root, "old.yaml", "RHEL_9_STIG", strings.Repeat("ab", 32), controls())
	if err == nil || !strings.Contains(err.Error(), "tailoring migrate") {
		t.Fatalf("legacy accepted: %v", err)
	}
}

func TestMigrateDropsEmptyAutoAndStripsHostPin(t *testing.T) {
	hash := strings.Repeat("cd", 32)
	old := "schema_version: 2\nbenchmark_id: Cisco_IOS_Router_NDM_STIG\nbenchmark_sha256: " + hash + "\nrules:\n  - stig_id: V-100\n    sv_id: SV-100r1_rule\n    status: auto\n  - stig_id: V-200\n    sv_id: SV-200r1_rule\n    status: not_applicable\n    comment: site uses external AAA\n"
	out, err := Migrate([]byte(old), Root, "Cisco_IOS_Router_NDM_STIG")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "V-100") || !strings.Contains(text, "V-200") || !strings.Contains(text, "schema_version: 3") || !strings.Contains(text, hash) {
		t.Fatalf("migrated root:\n%s", text)
	}
	hostOld := strings.Replace(old, "schema_version: 2", "schema_version: 1", 1)
	hostOut, err := Migrate([]byte(hostOld), Host, "Cisco_IOS_Router_NDM_STIG")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hostOut), "benchmark_sha256") {
		t.Fatalf("host pin survived:\n%s", hostOut)
	}
	parsed, err := Parse(hostOut, Host, "h.yaml", "Cisco_IOS_Router_NDM_STIG", hash, controls())
	if err != nil || len(parsed.Rules) != 1 {
		t.Fatalf("migrated host not readable: %v %+v", err, parsed)
	}
}

func TestMigrateImplicitRootKeepsCommentedAuto(t *testing.T) {
	old := "rules:\n  - rule_name: ssg_a\n    stig_id: V-100\n    sv_id: SV-100r1_rule\n    status: auto\n    comment: Remediation excluded.\n"
	out, err := Migrate([]byte(old), Root, "RHEL_9_STIG")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "rehash-me") || !strings.Contains(string(out), "rule_name: ssg_a") || !strings.Contains(string(out), "Remediation excluded.") {
		t.Fatalf("implicit migrate:\n%s", out)
	}
}

func TestRehashRewritesRootPin(t *testing.T) {
	body := []byte("schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: " + strings.Repeat("ab", 32) + "\nrules: []\n")
	next := strings.Repeat("ef", 32)
	dry, changed, err := RewriteRootHash(body, next)
	if err != nil || !changed || !bytesContain(dry, next) {
		t.Fatalf("rewrite: changed=%v err=%v\n%s", changed, err, dry)
	}
	again, changed, err := RewriteRootHash(dry, next)
	if err != nil || changed {
		t.Fatalf("second rewrite changed=%v err=%v", changed, err)
	}
	if string(again) != string(dry) && !bytesContain(again, next) {
		t.Fatalf("unchanged bytes lost pin: %s", again)
	}
}

func TestIsAdminDecisionSkipsScanPasses(t *testing.T) {
	if IsAdminDecision("not_a_finding", "XCCDF rule result: pass; check result: true") {
		t.Fatal("scan pass exported")
	}
	if IsAdminDecision("not_reviewed", "NOT REVIEWED — raw data") {
		t.Fatal("placeholder exported")
	}
	if IsAdminDecision("not_reviewed", "DRAFT: numeric V/SV mapping of SSG results; not an official DISA scan or ISSO-approved finding.") {
		t.Fatal("draft mapping sentence exported")
	}
	if IsAdminDecision("not_a_finding", "Not a Finding. This host's /etc/ssh/sshd_config has PermitRootLogin no. The SSG check passed; this is that result placed on the DISA rule id.") {
		t.Fatal("sshd sentence exported")
	}
	if IsAdminDecision("not_a_finding", "Not a Finding. Global spanning-tree loopguard default is present. This is the result of the saved running configuration on this device.") {
		t.Fatal("cisco device sentence exported")
	}
	if !IsAdminDecision("not_a_finding", "Reviewed with the system owner") {
		t.Fatal("human pass dropped")
	}
	if !IsAdminDecision("open", "Administrator confirmed a finding on this host.") {
		t.Fatal("admin finding dropped")
	}
	if IsAdminDecision("not_a_finding", "Not a Finding") {
		t.Fatal("bare scanner label exported")
	}
}

func TestHostWorksheetIsPartial(t *testing.T) {
	body := HostWorksheet("Cisco_IOS_Router_NDM_STIG", []WorksheetRow{
		{STIGID: "V-100", SVID: "SV-100r1_rule", Status: "not_a_finding", Comment: "XCCDF rule result: pass"},
		{STIGID: "V-200", SVID: "SV-200r1_rule", Status: "not_applicable", Comment: "Site accepts this session limit."},
		{STIGID: "V-300", SVID: "SV-300r1_rule", Status: "not_reviewed", Comment: "NOT REVIEWED — missing show output"},
	})
	text := string(body)
	if strings.Contains(text, "benchmark_sha256:") || strings.Contains(text, "V-100") || strings.Contains(text, "rule_name:") {
		t.Fatalf("worksheet not partial:\n%s", text)
	}
	if !strings.Contains(text, "schema_version: 3") || !strings.Contains(text, "status: not_applicable") || !strings.Contains(text, "Site accepts this session limit.") || !strings.Contains(text, "status: not_reviewed") {
		t.Fatalf("worksheet missing decisions:\n%s", text)
	}
}

func bytesContain(b []byte, s string) bool {
	return strings.Contains(string(b), s)
}
