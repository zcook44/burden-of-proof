package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ciscoPolicyBody(bench []byte, firstStatus, firstComment string, omitSecond bool) string {
	sum := sha256.Sum256(bench)
	body := "schema_version: 1\nbenchmark_id: Cisco_IOS_Router_NDM_STIG\nbenchmark_sha256: " + hex.EncodeToString(sum[:]) + "\nrules:\n  - stig_id: V-215662\n    sv_id: SV-215662r1269385_rule\n    status: " + firstStatus + "\n"
	if firstComment != "" {
		body += "    comment: " + firstComment + "\n"
	}
	if !omitSecond {
		body += "  - stig_id: V-215667\n    sv_id: SV-215667r1137875_rule\n    status: auto\n"
	}
	return body
}

func TestCiscoTailoringFullAutoPreservesLogicAndAdminOverrideIsVersioned(t *testing.T) {
	_, host, cfg, bench := ciscoFixture(t)
	benchmark, err := os.ReadFile(bench)
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(filepath.Dir(bench), "Cisco_IOS_Router_NDM_STIG.tailoring.yaml")
	if err := os.WriteFile(policy, []byte(ciscoPolicyBody(benchmark, "auto", "", false)), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"cisco-cklb", "--config", cfg, "--target", "router1.example.test", "--benchmark", bench}
	var out, errs bytes.Buffer
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("full auto policy rejected %d: %s", code, errs.String())
	}
	files, _ := filepath.Glob(filepath.Join(host, "*.cklb"))
	if len(files) != 1 {
		t.Fatalf("first output %v", files)
	}
	first := files[0]
	body, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	baseID := doc["id"]
	for _, item := range doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any) {
		row := item.(map[string]any)
		if row["status"] != "not_reviewed" || strings.Contains(row["comments"].(string), "Administrator") {
			t.Fatalf("auto policy modified candidate: %+v", row)
		}
	}
	var side map[string]any
	sideBytes, err := os.ReadFile(first + ".provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(sideBytes, &side); err != nil {
		t.Fatal(err)
	}
	tailored, ok := side["tailoring"].(map[string]any)
	if !ok || tailored["sha256"] != sha256Hex([]byte(ciscoPolicyBody(benchmark, "auto", "", false))) {
		t.Fatalf("tailoring hash absent: %+v", side)
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), "SKIP") {
		t.Fatalf("unchanged policy rerun %d: %s %s", code, out.String(), errs.String())
	}
	if err := os.WriteFile(policy, []byte(ciscoPolicyBody(benchmark, "open", "'Administrator confirmed a finding on this host.'", false)), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("admin override rejected %d: %s", code, errs.String())
	}
	files, _ = filepath.Glob(filepath.Join(host, "*.cklb"))
	if len(files) != 2 {
		t.Fatalf("policy edit overwrote existing checklist: %v", files)
	}
	var changed string
	for _, p := range files {
		if p != first {
			changed = p
		}
	}
	changedBody, err := os.ReadFile(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(changedBody, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["id"] == baseID {
		t.Fatal("policy edit reused CKLB identity")
	}
	rows := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)
	row := rows[0].(map[string]any)
	if row["status"] != "open" || !strings.Contains(row["comments"].(string), "Administrator confirmed") || !strings.Contains(row["finding_details"].(string), "not_reviewed") {
		t.Fatalf("admin decision not auditable: %+v", row)
	}
	if rows[1].(map[string]any)["status"] != "not_reviewed" {
		t.Fatal("other rule changed")
	}
	changedSide, err := os.ReadFile(changed + ".provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(changedSide, &side); err != nil {
		t.Fatal(err)
	}
	if side["checklist_sha256"] != sha256Hex(changedBody) || len(side["admin_overrides"].([]any)) != 1 {
		t.Fatalf("override provenance missing: %+v", side)
	}
}

func TestCiscoTailoringRejectsMissingRuleOrUncommentedOverrideBeforeWriting(t *testing.T) {
	for _, variant := range []string{"missing rule", "no comment", "wrong revision", "unknown field", "wrong benchmark hash", "duplicate rule", "second document"} {
		t.Run(variant, func(t *testing.T) {
			_, host, cfg, bench := ciscoFixture(t)
			benchmark, err := os.ReadFile(bench)
			if err != nil {
				t.Fatal(err)
			}
			body := ciscoPolicyBody(benchmark, "auto", "", variant == "missing rule")
			switch variant {
			case "no comment":
				body = ciscoPolicyBody(benchmark, "open", "", false)
			case "wrong revision":
				body = strings.Replace(body, "SV-215662r1269385_rule", "SV-215662r1_rule", 1)
			case "unknown field":
				body += "unknown: true\n"
			case "wrong benchmark hash":
				body = strings.Replace(body, sha256Hex(benchmark), strings.Repeat("0", 64), 1)
			case "duplicate rule":
				body = strings.Replace(body, "stig_id: V-215667", "stig_id: V-215662", 1)
			case "second document":
				body += "---\nrules: []\n"
			}
			policy := filepath.Join(filepath.Dir(bench), "Cisco_IOS_Router_NDM_STIG.tailoring.yaml")
			if err := os.WriteFile(policy, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errs bytes.Buffer
			if code := run([]string{"cisco-cklb", "--config", cfg, "--target", "router1.example.test", "--benchmark", bench, "--dry-run"}, &out, &errs); code == 0 || !strings.Contains(errs.String(), "tailoring") {
				t.Fatalf("invalid policy accepted %d: %s %s", code, out.String(), errs.String())
			}
			files, _ := filepath.Glob(filepath.Join(host, "*.cklb"))
			if len(files) != 0 {
				t.Fatalf("wrote invalid output: %v", files)
			}
		})
	}
}
