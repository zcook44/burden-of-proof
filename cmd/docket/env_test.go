package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain keeps a developer config file or DOCKET_* variable from changing
// command tests. Flag and env coverage sets the variables it needs itself.
func TestMain(m *testing.M) {
	_ = os.Setenv("DOCKET_CONFIG", filepath.Join(os.TempDir(), "docket-test-absent-config.yaml"))
	for _, key := range []string{
		"DOCKET_LIBRARY_ROOT",
		"DOCKET_INPUT_ROOT",
		"DOCKET_EVIDENCE_ROOT",
		"DOCKET_CISCO_MANIFEST",
		"DOCKET_OUTPUT_ROOT",
		"DOCKET_CHECKLIST_ROOT",
	} {
		_ = os.Unsetenv(key)
	}
	os.Exit(m.Run())
}
