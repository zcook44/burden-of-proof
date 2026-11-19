package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPreflightFailsClosedOnTailoring(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	repo := filepath.Join(filepath.Dir(file), "..", "..")
	bin := filepath.Join(t.TempDir(), "docket")
	build := exec.Command("go", "build", "-o", bin, "./cmd/docket")
	build.Dir = repo
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build docket: %v\n%s", err, out)
	}
	script := filepath.Join(repo, "scripts", "ceasefire-preflight.sh")

	root, _, library := tailoredFixture(t)
	bench, err := os.ReadFile(filepath.Join(library, "U_RHEL_9_STIG_V1R1_Manual-xccdf.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bench)
	good := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nbenchmark_sha256: " + hex.EncodeToString(sum[:]) + "\nrules: []\n"
	if err := os.WriteFile(filepath.Join(library, "RHEL_9_STIG.tailoring.yaml"), []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(library, "Nope_STIG.tailoring.yaml"), []byte("schema_version: 3\nbenchmark_id: Nope_STIG\nrules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script, "--converter", bin, "--input-root", root, "--library-root", library)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "tailoring validation failed") || strings.Contains(string(out), "Preflight complete") {
		t.Fatalf("broken root tailoring did not fail preflight: %v\n%s", err, out)
	}

	if err := os.Remove(filepath.Join(library, "Nope_STIG.tailoring.yaml")); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "node9.example.test", "extra")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	host := "schema_version: 3\nbenchmark_id: RHEL_9_STIG\nrules: []\n"
	if err := os.WriteFile(filepath.Join(nested, "RHEL_9_STIG.tailoring.yaml"), []byte(host), 0600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(script, "--converter", bin, "--input-root", root, "--library-root", library)
	out, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "nested") || strings.Contains(string(out), "Preflight complete") {
		t.Fatalf("nested tailoring file did not fail preflight: %v\n%s", err, out)
	}
}
