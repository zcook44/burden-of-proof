package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rhelPolicy(t *testing.T, library, status, comment string) string {
	t.Helper()
	bench, err := os.ReadFile(filepath.Join(library, "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bench)
	return fmt.Sprintf("schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: %s\nrules:\n  - rule_name: ssg_a\n    stig_id: V-100\n    sv_id: SV-100r1_rule\n    status: %s\n    comment: %q\n", hex.EncodeToString(sum[:]), status, comment)
}

func tailoredFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "inventory")
	host := filepath.Join(root, "node9.example.test")
	library := filepath.Join(t.TempDir(), "library")
	for _, dir := range []string{root, host, library} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	privateBench(t, host, "run.results.xml", sourceFixture(9))
	privateBench(t, library, "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml", officialFixture(9, 1))
	return root, host, library
}

func TestBatchAppliesPerOSTailoringAndVersionsChanges(t *testing.T) {
	root, host, library := tailoredFixture(t)
	policy := filepath.Join(library, "RHEL_9_STIG.tailoring.yaml")
	privateBench(t, library, filepath.Base(policy), rhelPolicy(t, library, "open", "Administrator reviewed the local configuration."))
	args := []string{"batch-cklb", "--input-root", root, "--library-root", library}
	var out, errs bytes.Buffer
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("tailored conversion %d: %s", code, errs.String())
	}
	files, _ := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if len(files) != 1 {
		t.Fatalf("expected one checklist: %v", files)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["status"] != "open" || !strings.Contains(row["comments"].(string), "Administrator reviewed the local configuration.") {
		t.Fatalf("policy not applied: %v", row)
	}
	sidecar, err := os.ReadFile(files[0] + ".provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var provenance map[string]any
	if err := json.Unmarshal(sidecar, &provenance); err != nil {
		t.Fatal(err)
	}
	// Check for new layered tailoring provenance structure
	tailored, ok := provenance["tailoring_root"].(map[string]any)
	if !ok || tailored["path"] != policy || tailored["sha256"] == "" {
		t.Fatalf("missing policy provenance: %v", provenance)
	}
	out.Reset()
	errs.Reset()
	// Second run may overwrite if provenance paths differ (warning shown)
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("rerun failed %d: %s %s", code, out.String(), errs.String())
	}
	privateBench(t, library, filepath.Base(policy), rhelPolicy(t, library, "not_a_finding", "Verified documented false positive by an administrator."))
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code != 0 || !strings.Contains(out.String(), "created=1 skipped=0") {
		t.Fatalf("changed policy %d: %s %s", code, out.String(), errs.String())
	}
	files, _ = filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if len(files) != 2 {
		t.Fatalf("policy change overwrote history: %v", files)
	}
}

func TestBatchRejectsMismatchedTailoringIDsWithoutWriting(t *testing.T) {
	root, host, library := tailoredFixture(t)
	privateBench(t, library, "RHEL_9_STIG.tailoring.yaml", strings.Replace(rhelPolicy(t, library, "not_a_finding", "Mismatched revision must fail."), "SV-100r1_rule", "SV-100r999_rule", 1))
	var out, errs bytes.Buffer
	if code := run([]string{"batch-cklb", "--input-root", root, "--library-root", library}, &out, &errs); code == 0 || !strings.Contains(errs.String(), "tailoring") {
		t.Fatalf("invalid policy accepted %d: %s", code, errs.String())
	}
	files, _ := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if len(files) != 0 {
		t.Fatalf("wrote invalid output: %v", files)
	}
}

func TestBatchAcceptsEmptyPerOSPolicy(t *testing.T) {
	for _, major := range []int{7, 10} {
		t.Run(fmt.Sprintf("RHEL%d", major), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "inventory")
			host := filepath.Join(root, fmt.Sprintf("node%d.example.test", major))
			library := filepath.Join(t.TempDir(), "library")
			for _, dir := range []string{root, host, library} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			privateBench(t, host, "run.results.xml", sourceFixture(major))
			privateBench(t, library, fmt.Sprintf("U_RHEL_%d_STIG_V1R1_Manual-xccdf.xml", major), officialFixture(major, 1))
			bench, err := os.ReadFile(filepath.Join(library, fmt.Sprintf("U_RHEL_%d_STIG_V1R1_Manual-xccdf.xml", major)))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(bench)
			privateBench(t, library, fmt.Sprintf("RHEL_%d_STIG.tailoring.yaml", major), fmt.Sprintf("schema_version: 3\nbenchmark_id: RHEL_%d_STIG\nbenchmark_sha256: %s\nrules: []\n", major, hex.EncodeToString(sum[:])))
			var out, errs bytes.Buffer
			if code := run([]string{"batch-cklb", "--input-root", root, "--library-root", library}, &out, &errs); code != 0 {
				t.Fatalf("empty policy rejected %d: %s", code, errs.String())
			}
			files, _ := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
			if len(files) != 1 {
				t.Fatalf("missing checklist: %v", files)
			}
			sidecar, err := os.ReadFile(files[0] + ".provenance.json")
			if err != nil {
				t.Fatal(err)
			}
			var provenance map[string]any
			if err := json.Unmarshal(sidecar, &provenance); err != nil {
				t.Fatal(err)
			}
			// Check for new layered tailoring provenance structure
			if provenance["tailoring_root"] == nil {
				t.Fatal("empty policy was not recorded in provenance")
			}
		})
	}
}

func TestBatchAutoPolicyKeepsObservedStatus(t *testing.T) {
	root, host, library := tailoredFixture(t)
	privateBench(t, library, "RHEL_9_STIG.tailoring.yaml", rhelPolicy(t, library, "auto", "Remediation excluded; assessment still comes from the scan."))
	var out, errs bytes.Buffer
	if code := run([]string{"batch-cklb", "--input-root", root, "--library-root", library}, &out, &errs); code != 0 {
		t.Fatalf("automatic status policy rejected %d: %s", code, errs.String())
	}
	files, _ := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	row := doc["stigs"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if row["status"] != "not_a_finding" || !strings.Contains(row["comments"].(string), "Remediation excluded") {
		t.Fatalf("auto policy overrode scan: %v", row)
	}
}
