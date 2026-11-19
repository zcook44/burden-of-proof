package checklist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeTailoring_SingleHost(t *testing.T) {
	files := []File{
		{
			Path: "/test/host1.cklb",
			Rules: []Rule{
				{
					Benchmark: "RHEL_9_STIG",
					Release:   "Release: 10 Benchmark Date: 30 Sep 2026",
					ID:        "V-257777",
					RuleID:    "SV-257777r1268251_rule",
					Status:    "not_a_finding",
					Comment:   "System is compliant",
				},
				{
					Benchmark: "RHEL_9_STIG",
					Release:   "Release: 10 Benchmark Date: 30 Sep 2026",
					ID:        "V-257778",
					RuleID:    "SV-257778r1268251_rule",
					Status:    "open",
					Comment:   "Requires remediation",
				},
			},
		},
	}

	results := AnalyzeTailoring(files, true)
	if len(results) != 1 {
		t.Fatalf("expected 1 tailoring file, got %d", len(results))
	}

	tf := results[0]
	if tf.Benchmark != "RHEL_9_STIG" {
		t.Errorf("expected benchmark RHEL_9_STIG, got %s", tf.Benchmark)
	}

	if len(tf.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(tf.Entries))
	}

	// Check first entry
	if tf.Entries[0].StigID != "V-257777" {
		t.Errorf("expected V-257777, got %s", tf.Entries[0].StigID)
	}
	if tf.Entries[0].Status != "not_a_finding" {
		t.Errorf("expected not_a_finding, got %s", tf.Entries[0].Status)
	}
}

func TestAnalyzeTailoring_MultipleHostsConsistent(t *testing.T) {
	files := []File{
		{
			Path: "/test/host1.cklb",
			Rules: []Rule{
				{
					Benchmark: "RHEL_9_STIG",
					Release:   "Release: 10",
					ID:        "V-100",
					RuleID:    "SV-100_rule",
					Status:    "not_a_finding",
					Comment:   "Same on all hosts",
				},
			},
		},
		{
			Path: "/test/host2.cklb",
			Rules: []Rule{
				{
					Benchmark: "RHEL_9_STIG",
					Release:   "Release: 10",
					ID:        "V-100",
					RuleID:    "SV-100_rule",
					Status:    "not_a_finding",
					Comment:   "Same on all hosts",
				},
			},
		},
	}

	results := AnalyzeTailoring(files, true)
	if len(results) != 1 {
		t.Fatalf("expected 1 tailoring file, got %d", len(results))
	}

	// Should have 1 entry since both hosts agree
	if len(results[0].Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(results[0].Entries))
	}
}

func TestAnalyzeTailoring_MultipleHostsInconsistent(t *testing.T) {
	files := []File{
		{
			Path: "/test/host1.cklb",
			Rules: []Rule{
				{
					Benchmark: "RHEL_9_STIG",
					Release:   "Release: 10",
					ID:        "V-100",
					RuleID:    "SV-100_rule",
					Status:    "not_a_finding",
					Comment:   "Host 1 comment",
				},
			},
		},
		{
			Path: "/test/host2.cklb",
			Rules: []Rule{
				{
					Benchmark: "RHEL_9_STIG",
					Release:   "Release: 10",
					ID:        "V-100",
					RuleID:    "SV-100_rule",
					Status:    "open", // Different status
					Comment:   "Host 2 comment",
				},
			},
		},
	}

	results := AnalyzeTailoring(files, true)

	// Should have no entries since hosts disagree
	if len(results) > 0 && len(results[0].Entries) != 0 {
		t.Errorf("expected 0 entries for inconsistent hosts, got %d", len(results[0].Entries))
	}
}

func TestAnalyzeTailoring_FilterNotReviewed(t *testing.T) {
	files := []File{
		{
			Path: "/test/host1.cklb",
			Rules: []Rule{
				{
					Benchmark: "RHEL_9_STIG",
					Release:   "Release: 10",
					ID:        "V-100",
					RuleID:    "SV-100_rule",
					Status:    "not_reviewed",
					Comment:   "NOT REVIEWED — raw data",
				},
				{
					Benchmark: "RHEL_9_STIG",
					Release:   "Release: 10",
					ID:        "V-101",
					RuleID:    "SV-101_rule",
					Status:    "not_a_finding",
					Comment:   "Actually reviewed",
				},
			},
		},
	}

	results := AnalyzeTailoring(files, true)

	// Should only have the reviewed one
	if len(results[0].Entries) != 1 {
		t.Errorf("expected 1 entry (filtered not_reviewed), got %d", len(results[0].Entries))
	}
	if results[0].Entries[0].StigID != "V-101" {
		t.Errorf("wrong entry kept after filtering")
	}
}

func TestFormatTailoringYAML(t *testing.T) {
	tf := TailoringFile{
		Benchmark: "RHEL_9_STIG",
		Release:   "Release: 10",
		Entries: []TailoringEntry{
			{
				RuleName: "PLACEHOLDER",
				StigID:   "V-257777",
				SvID:     "SV-257777r1268251_rule",
				Status:   "not_a_finding",
				Comment:  "Test comment",
			},
		},
	}

	yaml := FormatTailoringYAML(tf)

	// Check for required elements
	if !strings.Contains(yaml, "# RHEL_9_STIG tailoring") {
		t.Error("missing benchmark header")
	}
	if !strings.Contains(yaml, "rule_name: PLACEHOLDER") {
		t.Error("missing rule_name")
	}
	if !strings.Contains(yaml, "stig_id: V-257777") {
		t.Error("missing stig_id")
	}
	if !strings.Contains(yaml, "sv_id: SV-257777r1268251_rule") {
		t.Error("missing sv_id")
	}
	if !strings.Contains(yaml, "status: not_a_finding") {
		t.Error("missing status")
	}
	if !strings.Contains(yaml, "comment: \"Test comment\"") {
		t.Error("missing comment")
	}
	if !strings.Contains(yaml, "TODO: Fill in SSG rule name") {
		t.Error("missing placeholder warning")
	}
}

func TestFormatTailoringYAML_StatusMapping(t *testing.T) {
	// Test that not_reviewed maps to auto
	tf := TailoringFile{
		Benchmark: "RHEL_9_STIG",
		Release:   "Release: 10",
		Entries: []TailoringEntry{
			{
				RuleName: "PLACEHOLDER",
				StigID:   "V-100",
				SvID:     "SV-100_rule",
				Status:   "not_reviewed",
				Comment:  "Test",
			},
		},
	}

	yaml := FormatTailoringYAML(tf)
	if !strings.Contains(yaml, "status: auto") {
		t.Error("not_reviewed should map to auto status")
	}
}

func TestAnalyzeTailoring_CountsHostsByBenchmarkNotFirstRule(t *testing.T) {
	files := []File{{
		Path: "/test/host1.cklb",
		Rules: []Rule{
			{Benchmark: "RHEL_8_STIG", Release: "R8", ID: "V-1", RuleID: "SV-1_rule", Status: "open", Comment: "eight"},
			{Benchmark: "RHEL_9_STIG", Release: "R9", ID: "V-2", RuleID: "SV-2_rule", Status: "not_a_finding", Comment: "nine"},
		},
	}}
	results := AnalyzeTailoring(files, true)
	if len(results) != 2 {
		t.Fatalf("expected both benchmarks, got %#v", results)
	}
	if results[0].Benchmark != "RHEL_8_STIG" || results[1].Benchmark != "RHEL_9_STIG" {
		t.Fatalf("unexpected order: %#v", results)
	}
}

func TestFormatTailoringYAML_EscapesComment(t *testing.T) {
	tf := TailoringFile{
		Benchmark: "RHEL_9_STIG",
		Release:   "Release: 10",
		Entries: []TailoringEntry{{
			RuleName: "PLACEHOLDER",
			StigID:   "V-1",
			SvID:     "SV-1_rule",
			Status:   "open",
			Comment:  "say \"hi\"\nnext",
		}},
	}
	yaml := FormatTailoringYAML(tf)
	if !strings.Contains(yaml, `comment: "say \"hi\"\nnext"`) {
		t.Fatalf("comment was not escaped: %s", yaml)
	}
}

func TestWriteTailoringExports_RefusesMixedReleasesAndExistingFiles(t *testing.T) {
	dir := t.TempDir()
	entry := TailoringEntry{RuleName: "PLACEHOLDER", StigID: "V-1", SvID: "SV-1_rule", Status: "open", Comment: "a"}
	mixed := []TailoringFile{
		{Benchmark: "RHEL_9_STIG", Release: "A", Entries: []TailoringEntry{entry}},
		{Benchmark: "RHEL_9_STIG", Release: "B", Entries: []TailoringEntry{entry}},
	}
	if _, err := WriteTailoringExports(dir, mixed); err == nil {
		t.Fatal("expected mixed release refusal")
	}
	wrote, err := WriteTailoringExports(dir, mixed[:1])
	if err != nil || len(wrote) != 1 {
		t.Fatal(err)
	}
	info, err := os.Stat(wrote[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if _, err := WriteTailoringExports(dir, mixed[:1]); err == nil {
		t.Fatal("expected overwrite refusal")
	}
}

func TestWriteTailoringExports_RefusesSymlinkAndBadName(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	entry := TailoringEntry{RuleName: "PLACEHOLDER", StigID: "V-1", SvID: "SV-1_rule", Status: "open", Comment: "a"}
	sets := []TailoringFile{{Benchmark: "RHEL_9_STIG", Release: "A", Entries: []TailoringEntry{entry}}}
	if _, err := WriteTailoringExports(link, sets); err == nil {
		t.Fatal("symlink directory accepted")
	}
	bad := []TailoringFile{{Benchmark: "../outside", Release: "A", Entries: []TailoringEntry{entry}}}
	if _, err := WriteTailoringExports(real, bad); err == nil {
		t.Fatal("path-like benchmark id accepted")
	}
	if _, err := WriteTailoringExports(real, nil); err == nil {
		t.Fatal("empty export accepted")
	}
}
