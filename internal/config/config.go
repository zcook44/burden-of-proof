// Package config loads the shared docket and checkmate defaults file.
// Precedence for every setting is flag, then environment, then this file, then a built-in default.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// File is the on-disk defaults document.
// Paths are absolute or relative to the process working directory.
// An absent file is not an error. A present file must be this shape.
type File struct {
	LibraryRoot   string `yaml:"library_root"`
	InputRoot     string `yaml:"input_root"`
	EvidenceRoot  string `yaml:"evidence_root"`
	CiscoManifest string `yaml:"cisco_manifest"`
	OutputRoot    string `yaml:"output_root"`
	ChecklistRoot string `yaml:"checklist_root"`
}

// Load reads $DOCKET_CONFIG, otherwise $XDG_CONFIG_HOME/docket/config.yaml,
// otherwise ~/.config/docket/config.yaml. A missing file returns an empty File.
func Load() (File, string, error) {
	path := os.Getenv("DOCKET_CONFIG")
	if path == "" {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return File{}, "", nil
			}
			base = filepath.Join(home, ".config")
		}
		path = filepath.Join(base, "docket", "config.yaml")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return File{}, "", nil
		}
		return File{}, path, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg File
	if err := dec.Decode(&cfg); err != nil {
		return File{}, path, fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return File{}, path, fmt.Errorf("%s: only one YAML document is allowed", path)
	}
	return cfg, path, nil
}

// Resolve applies flag > environment > config file > built-in default.
// An empty string at any layer means "not set" and the next layer is used.
func Resolve(flagValue, envKey, fromFile, builtin string) string {
	if flagValue != "" {
		return flagValue
	}
	if envKey != "" {
		if v := os.Getenv(envKey); v != "" {
			return v
		}
	}
	if fromFile != "" {
		return fromFile
	}
	return builtin
}
