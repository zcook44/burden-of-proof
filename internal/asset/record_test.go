package asset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func validRecord(pre []byte) map[string]any {
	digest := sha256.Sum256(pre)
	return map[string]any{
		"schema_version": 1, "cycle_id": "2026-q4", "asset_fqdn": "node.example.test",
		"os_release": "rhel9", "role": "node", "baseline_state": "clean",
		"baseline_sha256": strings.Repeat("a", 64), "pre_scan_sha256": hex.EncodeToString(digest[:]),
		"lab_commit": strings.Repeat("b", 40),
	}
}

func TestValidateAcceptsExactAssetContract(t *testing.T) {
	pre := []byte("<synthetic-scan/>")
	data, err := json.Marshal(validRecord(pre))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data, "node.example.test", pre); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
}

func TestValidateRejectsContractViolations(t *testing.T) {
	pre := []byte("<synthetic-scan/>")
	cases := map[string]func(map[string]any){
		"schema bool":      func(r map[string]any) { r["schema_version"] = true },
		"missing field":    func(r map[string]any) { delete(r, "cycle_id") },
		"extra field":      func(r map[string]any) { r["extra"] = "unsafe" },
		"bad cycle":        func(r map[string]any) { r["cycle_id"] = "../escape" },
		"wrong host":       func(r map[string]any) { r["asset_fqdn"] = "other.example.test" },
		"bad fqdn":         func(r map[string]any) { r["asset_fqdn"] = "localhost" },
		"empty release":    func(r map[string]any) { r["os_release"] = "  " },
		"wrong role":       func(r map[string]any) { r["role"] = "other" },
		"dirty baseline":   func(r map[string]any) { r["baseline_state"] = "dirty" },
		"uppercase digest": func(r map[string]any) { r["baseline_sha256"] = strings.Repeat("A", 64) },
		"bad commit":       func(r map[string]any) { r["lab_commit"] = strings.Repeat("f", 39) },
		"wrong pre hash":   func(r map[string]any) { r["pre_scan_sha256"] = strings.Repeat("0", 64) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			record := validRecord(pre)
			change(record)
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(data, "node.example.test", pre); err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
	for name, data := range map[string]string{
		"duplicate key": `{"schema_version":1,"schema_version":1}`,
		"trailing data": `{}` + `{}`,
		"array":         `[]`,
		"invalid JSON":  `{`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate([]byte(data), "node.example.test", pre); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
}
