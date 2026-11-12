package draft

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

const ciscoBenchmark = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Cisco_IOS_Router_NDM_STIG"><title>Cisco Router NDM</title><version>3</version><plain-text id="release-info">Release: 9</plain-text><Group id="V-100"><title>Management</title><Rule id="SV-100r2_rule" severity="high" weight="10.0"><title>Protect access</title><version>IOS-ND-000001</version><fixtext>Review device settings</fixtext></Rule></Group><Group id="V-101"><title>Audit</title><Rule id="SV-101r1_rule" severity="medium"><title>Audit configuration</title></Rule></Group></Benchmark>`

func ciscoRules(t *testing.T, doc map[string]any) []any {
	t.Helper()
	stigs := doc["stigs"].([]any)
	if len(stigs) != 1 {
		t.Fatalf("STIG count: %d", len(stigs))
	}
	return stigs[0].(map[string]any)["rules"].([]any)
}

func TestCiscoConfigRendersAllRulesUnreviewedWithExistingRowShape(t *testing.T) {
	config := []byte("hostname lab-router\nservice password-encryption\n")
	doc, err := BuildCiscoConfig(config, "router.example.test", []byte(ciscoBenchmark))
	if err != nil {
		t.Fatal(err)
	}
	report, err := reconcile.Convert([]byte(scan), []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := Build(report, []byte(benchmark))
	if err != nil {
		t.Fatal(err)
	}
	baselineRow := baseline["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	rows := ciscoRules(t, doc)
	if len(rows) != 2 || doc["cklb_version"] != "1.0" || doc["target_data"].(map[string]any)["host_name"] != "router.example.test" {
		t.Fatalf("wrong checklist structure: %#v", doc)
	}
	stig := doc["stigs"].([]any)[0].(map[string]any)
	if stig["stig_id"] != "Cisco_IOS_Router_NDM_STIG" || stig["size"] != 2 || stig["release_info"] != "Release: 9" {
		t.Fatalf("wrong official metadata: %#v", stig)
	}
	for i, value := range rows {
		row := value.(map[string]any)
		for key := range baselineRow {
			if _, ok := row[key]; !ok {
				t.Errorf("row %d missing %q", i, key)
			}
		}
		for key := range row {
			if _, ok := baselineRow[key]; !ok {
				t.Errorf("row %d extra %q", i, key)
			}
		}
		if row["status"] != "not_reviewed" || row["comments"] == "" || row["finding_details"] == "" {
			t.Errorf("unsafe row %d: %#v", i, row)
		}
		text := row["comments"].(string) + row["finding_details"].(string)
		if !strings.Contains(text, "running config") || !strings.Contains(text, "manual") || strings.Contains(text, "SSG") || strings.Contains(text, "OpenSCAP") || strings.Contains(text, "password-encryption") {
			t.Errorf("misleading or leaked evidence: %q", text)
		}
		for _, field := range []string{"uuid", "stig_uuid", "group_id", "rule_id", "group_id_src", "rule_id_src", "severity", "rule_title"} {
			if row[field] == "" {
				t.Errorf("row %d empty %s", i, field)
			}
		}
	}
	if rows[0].(map[string]any)["group_id"] != "V-100" || rows[0].(map[string]any)["rule_id"] != "SV-100r2_rule" {
		t.Fatalf("official IDs lost: %#v", rows[0])
	}
	if !strings.Contains(rows[0].(map[string]any)["finding_details"].(string), hexHash(config)) || !strings.Contains(rows[0].(map[string]any)["finding_details"].(string), hexHash([]byte(ciscoBenchmark))) {
		t.Fatal("raw input hashes missing")
	}
}

func hexHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func TestCiscoConfigIdentityBindsInputsAndTarget(t *testing.T) {
	first, err := BuildCiscoConfig([]byte("hostname A\n"), "router", []byte(ciscoBenchmark))
	if err != nil {
		t.Fatal(err)
	}
	same, err := BuildCiscoConfig([]byte("hostname A\n"), "router", []byte(ciscoBenchmark))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, same) {
		t.Fatal("same inputs gave different checklist")
	}
	for _, tc := range []struct {
		config []byte
		target string
		bench  []byte
	}{
		{[]byte("hostname B\n"), "router", []byte(ciscoBenchmark)},
		{[]byte("hostname A\n"), "router2", []byte(ciscoBenchmark)},
		{[]byte("hostname A\n"), "router", []byte(ciscoBenchmark + " ")},
	} {
		other, err := BuildCiscoConfig(tc.config, tc.target, tc.bench)
		if err != nil {
			t.Fatal(err)
		}
		if first["id"] == other["id"] {
			t.Fatal("different input reused checklist identity")
		}
	}
}

func TestCiscoConfigRejectsInvalidInputs(t *testing.T) {
	replace := func(old, new string) []byte { return []byte(strings.Replace(ciscoBenchmark, old, new, 1)) }
	cases := []struct {
		name      string
		config    []byte
		target    string
		benchmark []byte
	}{
		{"empty config", nil, "router", []byte(ciscoBenchmark)},
		{"empty target", []byte("hostname A"), " ", []byte(ciscoBenchmark)},
		{"RHEL benchmark", []byte("hostname A"), "router", replace("Cisco_IOS_Router_NDM_STIG", "RHEL_9_STIG")},
		{"wrong namespace", []byte("hostname A"), "router", replace("xccdf/1.1", "xccdf/1.2")},
		{"wrong group ID", []byte("hostname A"), "router", replace("V-100", "V-100-extra")},
		{"wrong rule ID", []byte("hostname A"), "router", replace("SV-100r2_rule", "SV-100_rule")},
		{"mismatched numeric ID", []byte("hostname A"), "router", replace("SV-100r2_rule", "SV-101r2_rule")},
		{"duplicate group", []byte("hostname A"), "router", replace("V-101", "V-100")},
		{"duplicate rule", []byte("hostname A"), "router", replace("SV-101r1_rule", "SV-100r2_rule")},
		{"missing rule", []byte("hostname A"), "router", replace(`<Rule id="SV-101r1_rule" severity="medium"><title>Audit configuration</title></Rule>`, "")},
		{"two rules", []byte("hostname A"), "router", replace(`</Rule></Group>`, `</Rule><Rule id="SV-100r3_rule" severity="high"/></Group>`)},
		{"DTD", []byte("hostname A"), "router", []byte(`<!DOCTYPE Benchmark [<!ENTITY x "evil">]>` + ciscoBenchmark)},
		{"entity", []byte("hostname A"), "router", []byte(strings.Replace(ciscoBenchmark, "Management", "&x;", 1))},
		{"trailing XML", []byte("hostname A"), "router", []byte(ciscoBenchmark + `<Benchmark/>`)},
		{"foreign group namespace", []byte("hostname A"), "router", replace(`<Group id="V-100">`, `<Group xmlns="urn:wrong" id="V-100">`)},
		{"invalid severity", []byte("hostname A"), "router", replace(`severity="high"`, `severity="critical"`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if doc, err := BuildCiscoConfig(tc.config, tc.target, tc.benchmark); err == nil {
				t.Fatalf("accepted invalid input: %#v", doc)
			}
		})
	}
}
