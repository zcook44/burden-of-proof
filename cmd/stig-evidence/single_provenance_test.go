package main

import (
    "bytes"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
)

func TestSingleAssessmentSidecarRecordsAbsoluteInputPaths(t *testing.T) {
    root := t.TempDir()
    if err := os.Chmod(root, 0700); err != nil { t.Fatal(err) }
    scan := privateBench(t, root, "scan.results.xml", sourceFixture(9))
    benchmark := privateBench(t, root, "benchmark.xml", officialFixture(9, 2))
    html := privateBench(t, root, "scan.report.html", htmlFixture)
    cwd, err := os.Getwd()
    if err != nil { t.Fatal(err) }
    t.Cleanup(func() { _ = os.Chdir(cwd) })
    if err := os.Chdir(root); err != nil { t.Fatal(err) }
    var out, stderr bytes.Buffer
    if code := run([]string{"draft-cklb", "--assessment-view", "--scan", filepath.Base(scan), "--benchmark", filepath.Base(benchmark), "--html-report", filepath.Base(html), "--out", filepath.Join(root, "review.cklb")}, &out, &stderr); code != 0 {
        t.Fatalf("assessment failed: %d %s", code, stderr.String())
    }
    body, err := os.ReadFile("review.cklb.provenance.json")
    if err != nil { t.Fatal(err) }
    var side assessmentRecord
    if err := json.Unmarshal(body, &side); err != nil { t.Fatal(err) }
    for _, input := range []*evidenceInput{&side.Scan, &side.Benchmark, side.HTML} {
        if input == nil || !filepath.IsAbs(input.Path) { t.Fatalf("unverifiable path: %+v", input) }
    }
}
