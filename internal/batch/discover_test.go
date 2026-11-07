package batch

import (
	"os"
	"path/filepath"
	"testing"
)

func privateDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
}
func privateFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverNestedScanBundlesWithoutMixingRuns(t *testing.T) {
	root := t.TempDir()
	privateDir(t, root)
	nested := filepath.Join(root, "region", "node")
	privateDir(t, filepath.Join(root, "region"))
	privateDir(t, nested)
	for _, name := range []string{"scan-a.results.xccdf.xml", "scan-a.report.html", "scan-a.results.arf.xml", "scan-b.results.xccdf.xml", "scan-b.report.html", "scan-c.results.xml", "scan-c.report.html", "scan-c.stig-viewer.xccdf.xml", "unrelated.xml"} {
		privateFile(t, filepath.Join(nested, name))
	}
	found, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 3 || found[0].Prefix != "scan-a" || found[1].Prefix != "scan-b" || found[2].Prefix != "scan-c" || found[0].ARF == "" || found[1].ARF != "" || found[2].ARF != "" {
		t.Fatalf("bad bundles: %+v", found)
	}
	if found[0].Dir != nested || found[2].XCCDF != filepath.Join(nested, "scan-c.results.xml") {
		t.Fatalf("wrong paths: %+v", found)
	}
}
func TestDiscoverRejectsIncompleteBundle(t *testing.T) {
	root := t.TempDir()
	privateDir(t, root)
	privateFile(t, filepath.Join(root, "scan.results.xccdf.xml"))
	if _, err := Discover(root); err == nil {
		t.Fatal("missing HTML accepted")
	}
}
func TestDiscoverRejectsDuplicateXCCDFForOneRun(t *testing.T) {
	root := t.TempDir()
	privateDir(t, root)
	for _, name := range []string{"scan.results.xccdf.xml", "scan.results.xml", "scan.report.html"} {
		privateFile(t, filepath.Join(root, name))
	}
	if _, err := Discover(root); err == nil {
		t.Fatal("ambiguous XCCDF accepted")
	}
}
func TestDiscoverRejectsSymlinkDirectoryAndArtifact(t *testing.T) {
	root := t.TempDir()
	privateDir(t, root)
	other := t.TempDir()
	privateDir(t, other)
	if err := os.Symlink(other, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root); err == nil {
		t.Fatal("symlink directory accepted")
	}
	if err := os.Remove(filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	privateFile(t, filepath.Join(root, "scan.results.xccdf.xml"))
	if err := os.Symlink(filepath.Join(root, "scan.results.xccdf.xml"), filepath.Join(root, "scan.report.html")); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root); err == nil {
		t.Fatal("symlink artifact accepted")
	}
}
func TestDiscoverRejectsPublicDirectory(t *testing.T) {
	root := t.TempDir()
	privateDir(t, root)
	nested := filepath.Join(root, "node")
	privateDir(t, nested)
	if err := os.Chmod(nested, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root); err == nil {
		t.Fatal("public directory accepted")
	}
}
