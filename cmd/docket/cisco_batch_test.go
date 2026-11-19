package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCiscoBatchWritesOneReviewPagePerBenchmark(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	repo := filepath.Join(filepath.Dir(file), "..", "..")
	root := t.TempDir()
	lib := filepath.Join(root, "library")
	evidence := filepath.Join(root, "evidence", "ios-xe-switch-01")
	output := filepath.Join(root, "review")
	for _, dir := range []string{lib, evidence, output, filepath.Join(root, "evidence")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	copyPrivate := func(src, dst string) {
		t.Helper()
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	copyPrivate(filepath.Join(repo, "stig-library-cisco", "U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml"), filepath.Join(lib, "U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml"))
	copyPrivate(filepath.Join(repo, "stig-library-cisco", "U_Cisco_IOS-XE_Switch_NDM_STIG_V3R6_Manual-xccdf.xml"), filepath.Join(lib, "U_Cisco_IOS-XE_Switch_NDM_STIG_V3R6_Manual-xccdf.xml"))
	copyPrivate(filepath.Join(repo, "examples", "cisco-synthetic", "targets", "ios-xe-switch-01", "scan.running-config"), filepath.Join(evidence, "scan.running-config"))
	copyPrivate(filepath.Join(repo, "examples", "cisco-synthetic", "targets", "ios-xe-switch-01", "port-roles.csv"), filepath.Join(evidence, "port-roles.csv"))
	manifest := filepath.Join(root, "manifest.json")
	body := []byte(`{"schema_version":1,"devices":[{"host":"ios-xe-switch-01","platform":"ios-xe","benchmarks":["Cisco_IOS_XE_Switch_L2S_STIG","Cisco_IOS_XE_Switch_NDM_STIG"]}]}`)
	if err := os.WriteFile(manifest, body, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs strings.Builder
	code := run([]string{"cisco-batch", "--manifest", manifest, "--evidence-root", filepath.Join(root, "evidence"), "--library-root", lib, "--output-root", output}, &out, &errs)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errs.String())
	}
	index, err := os.ReadFile(filepath.Join(output, "index.html"))
	if err != nil || !strings.Contains(string(index), "Cisco_IOS_XE_Switch_L2S_STIG") || !strings.Contains(string(index), "Cisco_IOS_XE_Switch_NDM_STIG") {
		t.Fatalf("index: %v %s", err, index)
	}
	l2s := filepath.Join(output, "Cisco_IOS_XE_Switch_L2S_STIG", "ios-xe-switch-01")
	ndm := filepath.Join(output, "Cisco_IOS_XE_Switch_NDM_STIG", "ios-xe-switch-01")
	for _, dir := range []string{l2s, ndm} {
		pages, _ := filepath.Glob(filepath.Join(dir, "*.review.html"))
		checks, _ := filepath.Glob(filepath.Join(dir, "*.cklb"))
		if len(pages) != 1 || len(checks) != 1 {
			t.Fatalf("%s pages=%v checks=%v", dir, pages, checks)
		}
		page, err := os.ReadFile(pages[0])
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(page), "INTENTIONALLYINVALID") || strings.Contains(string(page), "SENSITIVE") {
			t.Fatal("review page copied a credential")
		}
	}
	page, err := os.ReadFile(mustOne(t, filepath.Join(l2s, "*.review.html")))
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	if !strings.Contains(text, "V-220650") || !strings.Contains(text, "data-status=\"open\"") || !strings.Contains(text, "V-220657") || !strings.Contains(text, ".tailoring.yaml") {
		t.Fatalf("L2S review page is missing the expected decisions")
	}
	ndmTailoring := strings.TrimSuffix(mustOne(t, filepath.Join(ndm, "*.cklb")), ".cklb") + ".tailoring.yaml"
	tailoring, err := os.ReadFile(ndmTailoring)
	if err != nil {
		t.Fatal(err)
	}
	suggestion := string(tailoring)
	if strings.Contains(suggestion, "benchmark_sha256:") || !strings.Contains(suggestion, "schema_version: 3") || !strings.Contains(suggestion, "status: not_reviewed") || !strings.Contains(suggestion, "tailoring") {
		t.Fatalf("tailoring suggestion is not a partial schema v3 host worksheet:\n%s", suggestion)
	}
	if !strings.Contains(out.String(), "open=") {
		t.Fatalf("batch did not report counts: %s", out.String())
	}
}

func mustOne(t *testing.T, pattern string) string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) != 1 {
		t.Fatalf("%s: %v %v", pattern, matches, err)
	}
	return matches[0]
}
