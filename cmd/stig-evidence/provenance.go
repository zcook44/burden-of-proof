package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

type evidenceInput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// assessmentProvenance binds exact checklist bytes to the complete source
// reconciliation without cluttering each displayed check and return value.
// This is a byte-identity record, not a signature or release authorization.
func assessmentProvenance(body []byte, report reconcile.Report, scanPath, benchmarkPath, htmlPath, arfPath string, html, arf []byte) ([]byte, error) {
	record := struct {
		SchemaVersion   int              `json:"schema_version"`
		ChecklistSHA256 string           `json:"checklist_sha256"`
		MappingMethod   string           `json:"mapping_method"`
		Scan            evidenceInput    `json:"scan"`
		Benchmark       evidenceInput    `json:"benchmark"`
		HTML            evidenceInput    `json:"html"`
		ARF             *evidenceInput   `json:"arf,omitempty"`
		Reconciliation  reconcile.Report `json:"reconciliation"`
	}{
		SchemaVersion:   1,
		ChecklistSHA256: sha256Hex(body),
		MappingMethod:   "numeric V/SV mapping; semantic check equivalence not independently verified",
		Scan:            evidenceInput{scanPath, report.ScanSHA256},
		Benchmark:       evidenceInput{benchmarkPath, report.BenchmarkSHA256},
		HTML:            evidenceInput{htmlPath, sha256Hex(html)},
		Reconciliation:  report,
	}
	if arfPath != "" {
		record.ARF = &evidenceInput{arfPath, sha256Hex(arf)}
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
