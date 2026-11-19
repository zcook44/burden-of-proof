package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
	"github.com/zcook44/burden-of-proof/internal/tailoring"
)

func TestLayeredTailoringMerge(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Create a minimal benchmark for testing
	benchmarkID := "RHEL_9_STIG"
	benchmark := []byte(`<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="RHEL_9_STIG">
	<Group id="V-257837"><Rule id="SV-257837r1268251_rule"></Rule></Group>
	<Group id="V-257781"><Rule id="SV-257781r1268251_rule"></Rule></Group>
	<Group id="V-257832"><Rule id="SV-257832r1155653_rule"></Rule></Group>
</Benchmark>`)

	// Create minimal report
	report := reconcile.Report{
		DISABenchmark: benchmarkID,
		Controls: []reconcile.Control{
			{GroupID: "V-257837", RuleID: "SV-257837r1268251_rule", Status: "open"},
			{GroupID: "V-257781", RuleID: "SV-257781r1268251_rule", Status: "open"},
			{GroupID: "V-257832", RuleID: "SV-257832r1155653_rule", Status: "open"},
		},
	}

	benchmarkSHA := sha256Hex(benchmark)

	// Test 1: Root only
	t.Run("RootOnly", func(t *testing.T) {
		rootDir := filepath.Join(tmpDir, "test1-root")
		hostDir := filepath.Join(tmpDir, "test1-host")
		os.MkdirAll(rootDir, 0700)
		os.MkdirAll(hostDir, 0700)

		rootFile := `schema_version: 3
benchmark_id: RHEL_9_STIG
benchmark_sha256: ` + benchmarkSHA + `
rules:
  - stig_id: V-257837
    sv_id: SV-257837r1268251_rule
    status: not_a_finding
    comment: "Test root override"
`
		os.WriteFile(filepath.Join(rootDir, benchmarkID+".tailoring.yaml"), []byte(rootFile), 0600)

		// RHEL tests use partial root inventory (false)
		rules, rootPath, _, hostPath, _, err := loadLayeredTailoring(rootDir, hostDir, benchmarkID, benchmark, report)
		if err != nil {
			t.Fatalf("loadLayeredTailoring failed: %v", err)
		}

		if rootPath == "" {
			t.Error("Expected root path to be set")
		}
		if hostPath != "" {
			t.Error("Expected host path to be empty")
		}
		if len(rules) != 1 {
			t.Fatalf("Expected 1 rule, got %d", len(rules))
		}
		if rules[0].STIGID != "V-257837" || rules[0].Status != "not_a_finding" || rules[0].Origin != "root" {
			t.Errorf("Rule mismatch: %+v", rules[0])
		}
	})

	// Test 2: Host only
	t.Run("HostOnly", func(t *testing.T) {
		rootDir := filepath.Join(tmpDir, "test2-root")
		hostDir := filepath.Join(tmpDir, "test2-host")
		os.MkdirAll(rootDir, 0700)
		os.MkdirAll(hostDir, 0700)

		hostFile := `schema_version: 3
benchmark_id: RHEL_9_STIG
rules:
  - stig_id: V-257781
    sv_id: SV-257781r1268251_rule
    status: not_applicable
    comment: "Test host override"
`
		os.WriteFile(filepath.Join(hostDir, benchmarkID+".tailoring.yaml"), []byte(hostFile), 0600)

		// RHEL tests use partial root inventory (false)
		rules, rootPath, _, hostPath, _, err := loadLayeredTailoring(rootDir, hostDir, benchmarkID, benchmark, report)
		if err != nil {
			t.Fatalf("loadLayeredTailoring failed: %v", err)
		}

		if rootPath != "" {
			t.Error("Expected root path to be empty")
		}
		if hostPath == "" {
			t.Error("Expected host path to be set")
		}
		if len(rules) != 1 {
			t.Fatalf("Expected 1 rule, got %d", len(rules))
		}
		if rules[0].STIGID != "V-257781" || rules[0].Status != "not_applicable" || rules[0].Origin != "host" {
			t.Errorf("Rule mismatch: %+v", rules[0])
		}
	})

	// Test 3: Root + Host merge (host overrides root)
	t.Run("RootAndHostMerge", func(t *testing.T) {
		rootDir := filepath.Join(tmpDir, "test3-root")
		hostDir := filepath.Join(tmpDir, "test3-host")
		os.MkdirAll(rootDir, 0700)
		os.MkdirAll(hostDir, 0700)

		rootFile := `schema_version: 3
benchmark_id: RHEL_9_STIG
benchmark_sha256: ` + benchmarkSHA + `
rules:
  - stig_id: V-257837
    sv_id: SV-257837r1268251_rule
    status: not_a_finding
    comment: "Root says not_a_finding"
  - stig_id: V-257781
    sv_id: SV-257781r1268251_rule
    status: open
    comment: "Root says open"
`

		hostFile := `schema_version: 3
benchmark_id: RHEL_9_STIG
rules:
  - stig_id: V-257837
    sv_id: SV-257837r1268251_rule
    status: auto
    comment: "Host reverts to auto - revert reason"
  - stig_id: V-257832
    sv_id: SV-257832r1155653_rule
    status: not_applicable
    comment: "Host adds a new rule"
`
		os.WriteFile(filepath.Join(rootDir, benchmarkID+".tailoring.yaml"), []byte(rootFile), 0600)
		os.WriteFile(filepath.Join(hostDir, benchmarkID+".tailoring.yaml"), []byte(hostFile), 0600)

		// RHEL tests use partial root inventory (false)
		rules, rootPath, _, hostPath, _, err := loadLayeredTailoring(rootDir, hostDir, benchmarkID, benchmark, report)
		if err != nil {
			t.Fatalf("loadLayeredTailoring failed: %v", err)
		}

		if rootPath == "" || hostPath == "" {
			t.Error("Expected both root and host paths to be set")
		}

		// Should have 3 rules total: V-257837 (host overrides), V-257781 (root only), V-257832 (host only)
		if len(rules) != 3 {
			t.Fatalf("Expected 3 rules, got %d", len(rules))
		}

		// Check that host override took precedence for V-257837
		found := false
		for _, r := range rules {
			if r.STIGID == "V-257837" {
				found = true
				if r.Status != "auto" || r.Origin != "host" {
					t.Errorf("Expected V-257837 to be auto from host, got status=%s origin=%s", r.Status, r.Origin)
				}
			}
		}
		if !found {
			t.Error("V-257837 not found in merged rules")
		}
	})

	// Test 4: A stale pin on the root file fails. A pin on the host file is rejected.
	t.Run("StaleBenchmarkHash", func(t *testing.T) {
		rootDir := filepath.Join(tmpDir, "test4-root")
		hostDir := filepath.Join(tmpDir, "test4-host")
		os.MkdirAll(rootDir, 0700)
		os.MkdirAll(hostDir, 0700)

		rootFile := `schema_version: 3
benchmark_id: RHEL_9_STIG
benchmark_sha256: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
rules:
  - stig_id: V-257781
    sv_id: SV-257781r1268251_rule
    status: not_applicable
    comment: "Test with wrong hash"
`
		os.WriteFile(filepath.Join(rootDir, benchmarkID+".tailoring.yaml"), []byte(rootFile), 0600)
		if _, _, _, _, _, err := loadLayeredTailoring(rootDir, hostDir, benchmarkID, benchmark, report); err == nil {
			t.Error("Expected error for stale root benchmark hash, got nil")
		}
		hostWithPin := `schema_version: 3
benchmark_id: RHEL_9_STIG
benchmark_sha256: ` + benchmarkSHA + `
rules:
  - stig_id: V-257781
    sv_id: SV-257781r1268251_rule
    status: not_applicable
    comment: "pin does not belong here"
`
		os.WriteFile(filepath.Join(hostDir, benchmarkID+".tailoring.yaml"), []byte(hostWithPin), 0600)
		os.WriteFile(filepath.Join(rootDir, benchmarkID+".tailoring.yaml"), []byte("schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: "+benchmarkSHA+"\nrules: []\n"), 0600)
		if _, _, _, _, _, err := loadLayeredTailoring(rootDir, hostDir, benchmarkID, benchmark, report); err == nil {
			t.Error("Expected error for benchmark_sha256 on a host file, got nil")
		}
	})

	// Test 5: Host override must have comment for auto (revert)
	t.Run("HostAutoMustHaveComment", func(t *testing.T) {
		rootDir := filepath.Join(tmpDir, "test5-root")
		hostDir := filepath.Join(tmpDir, "test5-host")
		os.MkdirAll(rootDir, 0700)
		os.MkdirAll(hostDir, 0700)

		hostFile := `schema_version: 3
benchmark_id: RHEL_9_STIG
rules:
  - stig_id: V-257781
    sv_id: SV-257781r1268251_rule
    status: auto
`
		os.WriteFile(filepath.Join(hostDir, benchmarkID+".tailoring.yaml"), []byte(hostFile), 0600)

		// RHEL tests use partial root inventory (false)
		_, _, _, _, _, err := loadLayeredTailoring(rootDir, hostDir, benchmarkID, benchmark, report)
		if err == nil {
			t.Error("Expected error for host auto without comment, got nil")
		}
	})
}

func TestBackwardCompatibility(t *testing.T) {
	tmpDir := t.TempDir()

	benchmarkID := "RHEL_9_STIG"
	benchmark := []byte(`<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="RHEL_9_STIG">
	<Group id="V-257837"><Rule id="SV-257837r1268251_rule"></Rule></Group>
</Benchmark>`)

	report := reconcile.Report{
		DISABenchmark: benchmarkID,
		Controls: []reconcile.Control{
			{GroupID: "V-257837", RuleID: "SV-257837r1268251_rule", Status: "open"},
		},
	}

	// Test old format (no schema_version, no benchmark_id/sha256) as root
	t.Run("OldFormatRoot", func(t *testing.T) {
		rootDir := filepath.Join(tmpDir, "old-root")
		hostDir := filepath.Join(tmpDir, "old-host")
		os.MkdirAll(rootDir, 0700)
		os.MkdirAll(hostDir, 0700)

		oldFile := `rules:
  - rule_name: xwindows_remove_packages
    stig_id: V-257837
    sv_id: SV-257837r1268251_rule
    status: auto
    comment: "Old format with comment on auto"
`
		os.WriteFile(filepath.Join(rootDir, benchmarkID+".tailoring.yaml"), []byte(oldFile), 0600)

		_, _, _, _, _, err := loadLayeredTailoring(rootDir, hostDir, benchmarkID, benchmark, report)
		if err == nil || !strings.Contains(err.Error(), "migrate") {
			t.Fatalf("old root format should be rejected with a migrate hint: %v", err)
		}
		benchmarkSHA := sha256Hex(benchmark)
		migrated, err := tailoring.Migrate([]byte(oldFile), tailoring.Root, benchmarkID)
		if err != nil {
			t.Fatal(err)
		}
		// The fixture benchmark hash is not in the old file, so pin it before a live read.
		pinned, changed, err := tailoring.RewriteRootHash(migrated, benchmarkSHA)
		if err != nil || !changed {
			t.Fatalf("rehash migrated file: changed=%v %v", changed, err)
		}
		// RewriteRootHash keeps schema 3 but may not be the digest until we wrote rehash-me.
		os.WriteFile(filepath.Join(rootDir, benchmarkID+".tailoring.yaml"), pinned, 0600)
		rules, _, _, _, _, err := loadLayeredTailoring(rootDir, hostDir, benchmarkID, benchmark, report)
		if err != nil {
			t.Fatalf("migrated root file rejected: %v", err)
		}

		if len(rules) != 1 {
			t.Fatalf("Expected 1 rule, got %d", len(rules))
		}
	})

	// Test that old format is rejected for host layer
	t.Run("OldFormatHostRejected", func(t *testing.T) {
		rootDir := filepath.Join(tmpDir, "old-host-root")
		hostDir := filepath.Join(tmpDir, "old-host-test")
		os.MkdirAll(rootDir, 0700)
		os.MkdirAll(hostDir, 0700)

		oldFile := `rules:
  - stig_id: V-257837
    sv_id: SV-257837r1268251_rule
    status: auto
    comment: "Old format not allowed for host"
`
		os.WriteFile(filepath.Join(hostDir, benchmarkID+".tailoring.yaml"), []byte(oldFile), 0600)

		// RHEL tests use partial root inventory (false)
		_, _, _, _, _, err := loadLayeredTailoring(rootDir, hostDir, benchmarkID, benchmark, report)
		if err == nil {
			t.Error("Old format should be rejected for host layer")
		}
	})
}
