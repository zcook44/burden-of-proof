package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

func TestAssessmentOutputNamesVersionReconciliationChanges(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inventory")
	host := filepath.Join(root, "node9.example.test")
	if err := os.MkdirAll(host, 0700); err != nil {
		t.Fatal(err)
	}
	scan := sourceFixture(9)
	bench := officialFixture(9, 2)
	privateBench(t, host, "run.results.xml", scan)
	benchmark := privateBench(t, root, "benchmark.xml", bench)
	var out, errs bytes.Buffer
	if code := run([]string{"batch-cklb", "--input-root", root, "--benchmark", benchmark}, &out, &errs); code != 0 {
		t.Fatalf("conversion %d %s", code, errs.String())
	}
	files, err := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files %v %v", files, err)
	}
	want := bundleDigest([]byte("assessment-provenance-v10"), []byte(scan), []byte(bench), nil, nil)[:16]
	if !strings.Contains(files[0], "-"+want+"-ASSESSMENT.cklb") {
		t.Fatalf("mapping revision did not version output name: %s", files[0])
	}
}

func TestBatchRerunFromDifferentWorkingDirectoryRetainsOriginalProvenance(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "inventory")
	host := filepath.Join(root, "node9.example.test")
	library := filepath.Join(base, "library")
	for _, dir := range []string{root, host, library} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	privateBench(t, host, "run.results.xml", sourceFixture(9))
	privateBench(t, host, "run.report.html", htmlFixture)
	privateBench(t, library, "U_RHEL_9_STIG_V1R2_Manual-xccdf.xml", officialFixture(9, 2))
	originalCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalCWD) })
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := run([]string{"batch-cklb", "--input-root", "inventory", "--library-root", "library"}, &out, &errs); code != 0 {
		t.Fatalf("initial: %d %s", code, errs.String())
	}
	files, err := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files %v %v", files, err)
	}
	side := files[0] + ".provenance.json"
	original, err := os.ReadFile(side)
	if err != nil {
		t.Fatal(err)
	}
	var recorded assessmentRecord
	if err := json.Unmarshal(original, &recorded); err != nil {
		t.Fatal(err)
	}
	for _, input := range []*evidenceInput{&recorded.Scan, &recorded.Benchmark, recorded.HTML} {
		if input != nil && !filepath.IsAbs(input.Path) {
			t.Fatalf("new sidecar contains relative source path: %q", input.Path)
		}
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if code := run([]string{"batch-cklb", "--input-root", root, "--library-root", library}, &out, &errs); code != 0 || !strings.Contains(out.String(), "created=0 skipped=1") {
		t.Fatalf("different cwd: %d %s %s", code, out.String(), errs.String())
	}
	after, err := os.ReadFile(side)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("original provenance was replaced")
	}
}

func TestBatchRerunWithIdenticalBenchmarkAtAnotherPrivatePath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inventory")
	host := filepath.Join(root, "node9.example.test")
	libraryA := filepath.Join(t.TempDir(), "library-a")
	libraryB := filepath.Join(t.TempDir(), "library-b")
	for _, dir := range []string{root, host, libraryA, libraryB} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	privateBench(t, host, "run.results.xml", sourceFixture(9))
	privateBench(t, host, "run.report.html", htmlFixture)
	name := "U_RHEL_9_STIG_V1R2_Manual-xccdf.xml"
	oldBenchmark := privateBench(t, libraryA, name, officialFixture(9, 2))
	privateBench(t, libraryB, name, officialFixture(9, 2))
	convert := func(library string) (int, string, string) {
		t.Helper()
		var out, errs bytes.Buffer
		code := run([]string{"batch-cklb", "--input-root", root, "--library-root", library}, &out, &errs)
		return code, out.String(), errs.String()
	}
	if code, out, errs := convert(libraryA); code != 0 || !strings.Contains(out, "created=1") {
		t.Fatalf("initial: %d %s %s", code, out, errs)
	}
	files, err := filepath.Glob(filepath.Join(host, "*-ASSESSMENT.cklb"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files %v %v", files, err)
	}
	side := files[0] + ".provenance.json"
	original, err := os.ReadFile(side)
	if err != nil {
		t.Fatal(err)
	}
	if code, out, errs := convert(libraryB); code != 0 || !strings.Contains(out, "created=0 skipped=1") {
		t.Fatalf("identical bytes at alternate path: %d %s %s", code, out, errs)
	}
	after, err := os.ReadFile(side)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("original provenance was replaced")
	}
	if err := os.WriteFile(oldBenchmark, []byte("modified original benchmark"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := convert(libraryB); code == 0 {
		t.Fatal("accepted stale provenance with unreadable original benchmark bytes")
	}
}

func TestRelativeOldProvenanceCannotSkipAcrossMatchingScanSuffix(t *testing.T) {
	base := t.TempDir()
	oldWD := filepath.Join(base, "old")
	newWD := filepath.Join(base, "new")
	for _, wd := range []string{oldWD, newWD} {
		host := filepath.Join(wd, "inventory", "node9.example.test")
		if err := os.MkdirAll(host, 0700); err != nil {
			t.Fatal(err)
		}
		privateBench(t, host, "run.results.xml", sourceFixture(9))
		privateBench(t, wd, "benchmark.xml", officialFixture(9, 2))
	}
	scanBytes := []byte(sourceFixture(9))
	benchBytes := []byte(officialFixture(9, 2))
	report, err := reconcile.Convert(scanBytes, benchBytes)
	if err != nil {
		t.Fatal(err)
	}
	old, err := assessmentProvenance([]byte("same checklist"), report, "inventory/node9.example.test/run.results.xml", "benchmark.xml", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	current, err := assessmentProvenance([]byte("same checklist"), report, filepath.Join(newWD, "inventory", "node9.example.test", "run.results.xml"), filepath.Join(newWD, "benchmark.xml"), "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(oldWD, "inventory", "node9.example.test", "run.results.xml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldWD, "benchmark.xml"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if equivalentProvenance(old, current) {
		t.Fatal("accepted old relative paths by suffix despite missing original scan and corrupt benchmark")
	}
	var out, errs bytes.Buffer
	args := []string{"batch-cklb", "--input-root", filepath.Join(newWD, "inventory"), "--benchmark", filepath.Join(newWD, "benchmark.xml")}
	if code := run(args, &out, &errs); code != 0 {
		t.Fatalf("initial conversion: %d %s", code, errs.String())
	}
	files, err := filepath.Glob(filepath.Join(newWD, "inventory", "node9.example.test", "*-ASSESSMENT.cklb"))
	if err != nil || len(files) != 1 {
		t.Fatalf("checklists: %v %v", files, err)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	old, err = assessmentProvenance(body, report, "inventory/node9.example.test/run.results.xml", "benchmark.xml", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[0]+".provenance.json", old, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if code := run(args, &out, &errs); code == 0 || strings.Contains(out.String(), "SKIP") {
		t.Fatalf("unsafe skip with untrustworthy relative sidecar: %d %s %s", code, out.String(), errs.String())
	}
}
