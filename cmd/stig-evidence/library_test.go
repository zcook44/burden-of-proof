package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sourceRHEL9 = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL-9"><TestResult><target>node.example.test</target></TestResult></Benchmark>`

func benchmarkFixture(version, release string) string {
	return `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG"><title>RHEL 9 STIG</title><version>` + version + `</version><plain-text id="release-info">Release: ` + release + ` Benchmark Date: 30 Sep 2026</plain-text><Group id="V-100"><Rule id="SV-100r1_rule" severity="high"/></Group></Benchmark>`
}

func privateBench(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLatestBenchmarkUsesVersionThenReleaseNotScanTimestamp(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	privateBench(t, root, "U_RHEL_9_STIG_V2R9_Manual-xccdf.xml", benchmarkFixture("2", "9"))
	expected := privateBench(t, root, "U_RHEL_9_STIG_V2R10_Manual-xccdf.xml", benchmarkFixture("2", "10"))
	nested := filepath.Join(root, "next-quarter")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	privateBench(t, nested, "U_RHEL_9_STIG_V1R99_Manual-xccdf.xml", benchmarkFixture("1", "99"))
	path, data, err := latestBenchmark(root, []byte(sourceRHEL9))
	if err != nil || path != expected || !strings.Contains(string(data), "Release: 10") {
		t.Fatalf("path=%q err=%v", path, err)
	}
}

func TestLatestBenchmarkRejectsAmbiguousRelease(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	privateBench(t, root, "U_RHEL_9_STIG_V2R10_Manual-xccdf.xml", benchmarkFixture("2", "10"))
	nested := filepath.Join(root, "copy")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	privateBench(t, nested, "U_RHEL_9_STIG_V2R10_Manual-xccdf.xml", benchmarkFixture("2", "10"))
	if _, _, err := latestBenchmark(root, []byte(sourceRHEL9)); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous release accepted: %v", err)
	}
}

func TestLatestBenchmarkRejectsMismatchedMetadata(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	privateBench(t, root, "U_RHEL_9_STIG_V2R10_Manual-xccdf.xml", benchmarkFixture("2", "9"))
	if _, _, err := latestBenchmark(root, []byte(sourceRHEL9)); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("mismatched release accepted: %v", err)
	}
}

func TestLatestBenchmarkRejectsUnsupportedSourceAndSymlink(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	p := privateBench(t, root, "U_RHEL_9_STIG_V2R10_Manual-xccdf.xml", benchmarkFixture("2", "10"))
	if _, _, err := latestBenchmark(root, []byte(strings.Replace(sourceRHEL9, "RHEL-9", "RHEL-6", 1))); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("wrong source accepted: %v", err)
	}
	if err := os.Symlink(p, filepath.Join(root, "link.xml")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := latestBenchmark(root, []byte(sourceRHEL9)); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink accepted: %v", err)
	}
}
