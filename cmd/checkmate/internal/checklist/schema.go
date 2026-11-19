package checklist

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Schema is an operator-supplied JSON Schema. No schema bytes are distributed
// with Checkmate, and no external references are fetched by the compiler.
type Schema struct{ compiled *jsonschema.Schema }

// LoadSchema requires a local regular JSON Schema Draft 2019-09 file.
func LoadSchema(path string) (*Schema, error) {
	if filepath.Ext(path) != ".json" {
		return nil, fmt.Errorf("schema must be an extracted .json file: %s", path)
	}
	if _, err := regular(path); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid schema JSON: %w", err)
	}
	if doc["$schema"] != "https://json-schema.org/draft/2019-09/schema" {
		return nil, fmt.Errorf("schema must declare JSON Schema Draft 2019-09")
	}
	c := jsonschema.NewCompiler() // no URL loader: external references fail closed
	if err := c.AddResource("checkmate-schema.json", doc); err != nil {
		return nil, fmt.Errorf("load schema: %w", err)
	}
	compiled, err := c.Compile("checkmate-schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	return &Schema{compiled: compiled}, nil
}

func (s *Schema) Validate(data []byte) error {
	if s == nil {
		return fmt.Errorf("schema is not loaded")
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("invalid CKLB JSON: %w", err)
	}
	if err := s.compiled.Validate(doc); err != nil {
		return fmt.Errorf("CKLB schema: %w", err)
	}
	return nil
}
