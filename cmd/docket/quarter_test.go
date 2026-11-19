package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuarterFailsClosedOnTailoringThenDryRuns(t *testing.T) {
	root, _, library := tailoredFixture(t)
	bench, err := os.ReadFile(filepath.Join(library, "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bench)
	bad := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: " + strings.Repeat("0", 64) + "\nrules: []\n"
	if err := os.WriteFile(filepath.Join(library, "RHEL_9_STIG.tailoring.yaml"), []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := run([]string{"quarter", "--library-root", library, "--input-root", root, "--dry-run"}, &out, &errs); code == 0 || !strings.Contains(errs.String(), "tailoring check failed") {
		t.Fatalf("stale pin did not fail the quarter: %d\n%s\n%s", code, out.String(), errs.String())
	}
	good := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: " + hex.EncodeToString(sum[:]) + "\nrules: []\n"
	if err := os.WriteFile(filepath.Join(library, "RHEL_9_STIG.tailoring.yaml"), []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if code := run([]string{"quarter", "--library-root", library, "--input-root", root, "--dry-run"}, &out, &errs); code != 0 {
		t.Fatalf("dry quarter %d: %s", code, errs.String())
	}
	if !strings.Contains(out.String(), "QUARTER DRY RUN") || !strings.Contains(out.String(), "DRY RUN") {
		t.Fatalf("dry quarter output: %s", out.String())
	}
	matches, _ := filepath.Glob(filepath.Join(root, "*", "*.cklb"))
	if len(matches) != 0 {
		t.Fatalf("dry quarter wrote checklists: %v", matches)
	}
	out.Reset()
	errs.Reset()
	if code := run([]string{"quarter", "--library-root", library, "--input-root", root}, &out, &errs); code != 0 {
		t.Fatalf("quarter %d: %s %s", code, out.String(), errs.String())
	}
	matches, _ = filepath.Glob(filepath.Join(root, "*", "*.cklb"))
	if len(matches) != 1 || !strings.Contains(out.String(), "QUARTER complete") {
		t.Fatalf("quarter did not write one checklist: %v\n%s", matches, out.String())
	}
}

func TestRehashUpdatesRootPinOnly(t *testing.T) {
	_, host, library := tailoredFixture(t)
	bench, err := os.ReadFile(filepath.Join(library, "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bench)
	want := hex.EncodeToString(sum[:])
	rootFile := filepath.Join(library, "RHEL_9_STIG.tailoring.yaml")
	stale := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: " + strings.Repeat("ab", 32) + "\nrules: []\n"
	if err := os.WriteFile(rootFile, []byte(stale), 0600); err != nil {
		t.Fatal(err)
	}
	hostFile := filepath.Join(host, "RHEL_9_STIG.tailoring.yaml")
	hostBody := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nrules:\n  - stig_id: V-100\n    sv_id: SV-100r1_rule\n    status: not_applicable\n    comment: this host is exempt\n"
	if err := os.WriteFile(hostFile, []byte(hostBody), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := run([]string{"tailoring", "rehash", "--library-root", library, "--dry-run"}, &out, &errs); code != 0 || !strings.Contains(out.String(), "REHASH") || !strings.Contains(out.String(), "DRY RUN") {
		t.Fatalf("rehash dry-run %d: %s %s", code, out.String(), errs.String())
	}
	body, err := os.ReadFile(rootFile)
	if err != nil || string(body) != stale {
		t.Fatalf("dry-run wrote the pin: %s", body)
	}
	out.Reset()
	if code := run([]string{"tailoring", "rehash", "--library-root", library}, &out, &errs); code != 0 {
		t.Fatalf("rehash %d: %s", code, errs.String())
	}
	body, err = os.ReadFile(rootFile)
	if err != nil || !strings.Contains(string(body), want) {
		t.Fatalf("pin not rewritten: %s %v", body, err)
	}
	hostNow, err := os.ReadFile(hostFile)
	if err != nil || string(hostNow) != hostBody || strings.Contains(string(hostNow), "benchmark_sha256") {
		t.Fatalf("host file changed: %s", hostNow)
	}
}

func TestConfigFeedsQuarter(t *testing.T) {
	root, _, library := tailoredFixture(t)
	bench, err := os.ReadFile(filepath.Join(library, "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bench)
	policy := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: " + hex.EncodeToString(sum[:]) + "\nrules: []\n"
	if err := os.WriteFile(filepath.Join(library, "RHEL_9_STIG.tailoring.yaml"), []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	text := "library_root: " + library + "\ninput_root: " + root + "\n"
	if err := os.WriteFile(cfg, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKET_CONFIG", cfg)
	t.Setenv("DOCKET_LIBRARY_ROOT", "")
	var out, errs bytes.Buffer
	if code := run([]string{"quarter", "--dry-run"}, &out, &errs); code != 0 {
		t.Fatalf("config quarter %d: %s %s", code, out.String(), errs.String())
	}
	if !strings.Contains(out.String(), library) && !strings.Contains(out.String(), "VALIDATION PASSED") {
		t.Fatalf("config was not used: %s", out.String())
	}
}

func TestQuarterSkipsAbsentPlatforms(t *testing.T) {
	root, _, library := tailoredFixture(t)
	bench, err := os.ReadFile(filepath.Join(library, "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bench)
	policy := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: " + hex.EncodeToString(sum[:]) + "\nrules: []\n"
	if err := os.WriteFile(filepath.Join(library, "RHEL_9_STIG.tailoring.yaml"), []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty-inventory")
	if err := os.Mkdir(empty, 0700); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := run([]string{"quarter", "--library-root", library, "--input-root", empty, "--dry-run"}, &out, &errs); code == 0 || !strings.Contains(out.String(), "skipping RHEL") {
		t.Fatalf("empty RHEL tree should skip and then stop: %d\n%s\n%s", code, out.String(), errs.String())
	}
	out.Reset()
	errs.Reset()
	if code := run([]string{"quarter", "--rhel", "--library-root", library, "--input-root", empty}, &out, &errs); code == 0 || !strings.Contains(errs.String(), "no OpenSCAP scan bundles") {
		t.Fatalf("--rhel with no scans: %d\n%s\n%s", code, out.String(), errs.String())
	}
	out.Reset()
	errs.Reset()
	if code := run([]string{"quarter", "--cisco", "--library-root", library}, &out, &errs); code == 0 || !strings.Contains(errs.String(), "--cisco needs") {
		t.Fatalf("--cisco without inputs: %d\n%s\n%s", code, out.String(), errs.String())
	}
	out.Reset()
	errs.Reset()
	if code := run([]string{"quarter", "--cisco", "--library-root", library, "--input-root", root, "--dry-run"}, &out, &errs); code == 0 || !strings.Contains(out.String(), "skipping RHEL (--cisco)") || strings.Contains(out.String(), "batch-cklb") {
		t.Fatalf("--cisco must not convert RHEL scans: %d\n%s\n%s", code, out.String(), errs.String())
	}
}

func TestUnmatchedRootTailoringFails(t *testing.T) {
	_, _, library := tailoredFixture(t)
	body := []byte("this is not tailoring\n")
	if err := os.WriteFile(filepath.Join(library, "Nope_STIG.tailoring.yaml"), body, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	code := run([]string{"tailoring", "check", "--library-root", library}, &out, &errs)
	if code == 0 || !strings.Contains(errs.String(), "ERROR:") || strings.Contains(out.String(), "VALIDATION PASSED") {
		t.Fatalf("unmatched tailoring file was not fatal: %d\n%s\n%s", code, out.String(), errs.String())
	}
}

func TestPublicBenchmarkModeIsReadable(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := privateBench(t, root, "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml", benchmarkFixture("1", "1"))
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	got, _, err := latestBenchmark(root, []byte(sourceRHEL9))
	if err != nil || got != path {
		t.Fatalf("public benchmark rejected: %v %s", err, got)
	}
}
