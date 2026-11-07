// Package asset validates the versioned, non-secret lab-to-evidence handoff.
package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var (
	cycleID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	fqdn      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitHex = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

var fields = []string{"schema_version", "cycle_id", "asset_fqdn", "os_release", "role", "baseline_state", "baseline_sha256", "pre_scan_sha256", "lab_commit"}

// Validate checks a v1 asset record against the exact pre-scan bytes and host.
// Callers should snapshot file inputs before invoking it; a digest is not attestation.
func Validate(data []byte, host string, pre []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("invalid asset record JSON object")
	}
	record := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid asset record key: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("invalid asset record key")
		}
		if _, exists := record[key]; exists {
			return fmt.Errorf("duplicate asset record field: %s", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("invalid field %s: %w", key, err)
		}
		record[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("invalid asset record closing delimiter")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing asset record data")
	}
	if len(record) != len(fields) {
		return fmt.Errorf("asset record fields differ from v1 contract")
	}
	for _, key := range fields {
		if _, ok := record[key]; !ok {
			return fmt.Errorf("missing asset record field: %s", key)
		}
	}
	if string(record["schema_version"]) != "1" {
		return fmt.Errorf("invalid schema_version")
	}
	get := func(key string) (string, error) {
		var value string
		if err := json.Unmarshal(record[key], &value); err != nil || string(record[key]) == "null" {
			return "", fmt.Errorf("invalid %s", key)
		}
		return value, nil
	}
	values := make(map[string]string)
	for _, key := range fields[1:] {
		value, err := get(key)
		if err != nil {
			return err
		}
		values[key] = value
	}
	if !cycleID.MatchString(values["cycle_id"]) {
		return fmt.Errorf("invalid cycle_id")
	}
	if len(values["asset_fqdn"]) > 253 || !fqdn.MatchString(values["asset_fqdn"]) || values["asset_fqdn"] != host {
		return fmt.Errorf("asset_fqdn must match exact host FQDN")
	}
	if strings.TrimSpace(values["os_release"]) == "" {
		return fmt.Errorf("invalid os_release")
	}
	switch values["role"] {
	case "node", "gui", "controller":
	default:
		return fmt.Errorf("invalid role")
	}
	if values["baseline_state"] != "clean" {
		return fmt.Errorf("baseline_state must be clean")
	}
	if !sha256Hex.MatchString(values["baseline_sha256"]) {
		return fmt.Errorf("invalid baseline_sha256")
	}
	if !sha256Hex.MatchString(values["pre_scan_sha256"]) {
		return fmt.Errorf("invalid pre_scan_sha256")
	}
	if !commitHex.MatchString(values["lab_commit"]) {
		return fmt.Errorf("invalid lab_commit")
	}
	digest := sha256.Sum256(pre)
	if values["pre_scan_sha256"] != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("pre_scan_sha256 differs from supplied pre-scan")
	}
	return nil
}
