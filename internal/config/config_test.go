package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	t.Setenv("DOCKET_LIBRARY_ROOT", "from-env")
	if got := Resolve("from-flag", "DOCKET_LIBRARY_ROOT", "from-file", "builtin"); got != "from-flag" {
		t.Fatalf("flag: %s", got)
	}
	if got := Resolve("", "DOCKET_LIBRARY_ROOT", "from-file", "builtin"); got != "from-env" {
		t.Fatalf("env: %s", got)
	}
	t.Setenv("DOCKET_LIBRARY_ROOT", "")
	if got := Resolve("", "DOCKET_LIBRARY_ROOT", "from-file", "builtin"); got != "from-file" {
		t.Fatalf("file: %s", got)
	}
	if got := Resolve("", "DOCKET_LIBRARY_ROOT", "", "builtin"); got != "builtin" {
		t.Fatalf("builtin: %s", got)
	}
	if got := Resolve("", "", "", ""); got != "" {
		t.Fatalf("empty: %q", got)
	}
}

func TestLoadFromDOCKET_CONFIG(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "library_root: /library\ninput_root: /scans\nevidence_root: /evidence\ncisco_manifest: /evidence/devices.json\noutput_root: /out\nchecklist_root: /cklb\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKET_CONFIG", path)
	cfg, gotPath, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != path || cfg.LibraryRoot != "/library" || cfg.InputRoot != "/scans" || cfg.EvidenceRoot != "/evidence" || cfg.CiscoManifest != "/evidence/devices.json" || cfg.OutputRoot != "/out" || cfg.ChecklistRoot != "/cklb" {
		t.Fatalf("cfg %+v path %s", cfg, gotPath)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	t.Setenv("DOCKET_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	cfg, path, err := Load()
	if err != nil || path != "" || cfg != (File{}) {
		t.Fatalf("missing: %+v %q %v", cfg, path, err)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("library_root: /library\nnot_a_setting: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKET_CONFIG", path)
	if _, _, err := Load(); err == nil {
		t.Fatal("unknown field accepted")
	}
}
