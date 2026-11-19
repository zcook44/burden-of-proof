package checklist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSchema = `{"$schema":"https://json-schema.org/draft/2019-09/schema","type":"object","required":["title"],"properties":{"title":{"type":"string"}},"additionalProperties":false}`

func schemaFile(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "schema.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSchemaCheckIsOptInForEdits(t *testing.T) {
	root := t.TempDir()
	path := fixture(t, root, "one.cklb", "open") // structurally usable, not schema-valid
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Preflight(f, nil); err != nil {
		t.Fatalf("default preflight rejected schema-invalid file: %v", err)
	}
	schema, err := LoadSchema(schemaFile(t, testSchema))
	if err != nil {
		t.Fatal(err)
	}
	if err := Preflight(f, schema); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("opt-in schema did not reject file: %v", err)
	}
}

func TestUserSuppliedSchemaValidatesOffline(t *testing.T) {
	schema, err := LoadSchema(schemaFile(t, testSchema))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate([]byte(`{"title":"valid"}`)); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate([]byte(`{"extra":true}`)); err == nil {
		t.Fatal("required and extra fields were not checked")
	}
}

func TestSchemaPathMustBeReadableRegularJSON201909(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadSchema(dir); err == nil {
		t.Fatal("accepted directory")
	}
	other := schemaFile(t, testSchema)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSchema(link); err == nil {
		t.Fatal("accepted symlink")
	}
	for _, doc := range []string{`{"type":"object"}`, `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}`, `not json`, `{"$schema":"https://json-schema.org/draft/2019-09/schema","$ref":"https://example.invalid/another.json"}`} {
		if _, err := LoadSchema(schemaFile(t, doc)); err == nil {
			t.Fatalf("accepted unsupported schema %s", doc)
		}
	}
}
