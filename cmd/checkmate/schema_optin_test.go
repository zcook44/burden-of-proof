package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zcook44/checkmate/internal/checklist"
)

func TestTUIEditUsesSchemaOnlyWhenRequested(t *testing.T) {
	root := t.TempDir()
	p := sample(t, root, "r1", "open")
	schemaPath := filepath.Join(t.TempDir(), "schema.json")
	doc := `{"$schema":"https://json-schema.org/draft/2019-09/schema","type":"object","required":["title"],"properties":{"title":{"type":"string"}},"additionalProperties":false}`
	if err := os.WriteFile(schemaPath, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	schema, err := checklist.LoadSchema(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	files, err := checklist.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(files)
	m.schema = schema
	if !strings.Contains(m.View(), "Schema: ON") {
		t.Fatal("TUI does not disclose opt-in validation")
	}
	m = key(m, "space")
	m = key(m, "e")
	m = key(m, "1")
	m = key(m, "x")
	m = key(m, "enter")
	m = key(m, "y")
	if !strings.Contains(m.message, "schema") {
		t.Fatalf("schema not checked in TUI: %s", m.message)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"comments":"old"`) {
		t.Fatal("wrote invalid file", string(b))
	}
}
