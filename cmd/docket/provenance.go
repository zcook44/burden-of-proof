package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"

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

type assessmentRecord struct {
	SchemaVersion   int              `json:"schema_version"`
	ChecklistSHA256 string           `json:"checklist_sha256"`
	MappingMethod   string           `json:"mapping_method"`
	Scan            evidenceInput    `json:"scan"`
	Benchmark       evidenceInput    `json:"benchmark"`
	HTML            *evidenceInput   `json:"html,omitempty"`
	ARF             *evidenceInput   `json:"arf,omitempty"`
	Tailoring       *evidenceInput   `json:"tailoring,omitempty"`
	Reconciliation  reconcile.Report `json:"reconciliation"`
}

// equivalentProvenance accepts an old sidecar only when its sole difference
// is where byte-identical private inputs were read. Retain the old record and
// its paths; never rewrite audit provenance merely to make a rerun pass.
func equivalentProvenance(existing, expected []byte) bool {
	var old, current assessmentRecord
	if json.Unmarshal(existing, &old) != nil || json.Unmarshal(expected, &current) != nil {
		return false
	}
	canonical, err := json.MarshalIndent(old, "", "  ")
	if err != nil || !bytes.Equal(append(canonical, '\n'), existing) {
		return false // reject unknown fields, duplicates, or edited serialization
	}
	for _, input := range []*evidenceInput{&old.Scan, &old.Benchmark, old.HTML, old.ARF, old.Tailoring} {
		if input == nil {
			continue
		}
		if input.Path == "" {
			return false
		}
		path := input.Path
		if !filepath.IsAbs(path) {
			return false // old relative paths have no trustworthy recorded base
		}
		data, err := readPrivate(path)
		if err != nil || sha256Hex(data) != input.SHA256 {
			return false
		}
	}
	old.Scan.Path = current.Scan.Path
	old.Benchmark.Path = current.Benchmark.Path
	if old.HTML != nil && current.HTML != nil {
		old.HTML.Path = current.HTML.Path
	}
	if old.ARF != nil && current.ARF != nil {
		old.ARF.Path = current.ARF.Path
	}
	if old.Tailoring != nil && current.Tailoring != nil {
		old.Tailoring.Path = current.Tailoring.Path
	}
	canonical, err = json.MarshalIndent(old, "", "  ")
	return err == nil && bytes.Equal(append(canonical, '\n'), expected)
}

// assessmentProvenance binds exact checklist bytes to the complete source
// reconciliation without cluttering each displayed check and return value.
// This is a byte-identity record, not a signature or release authorization.
func assessmentProvenance(body []byte, report reconcile.Report, scanPath, benchmarkPath, htmlPath, arfPath string, html, arf []byte, tailoring ...*evidenceInput) ([]byte, error) {
	record := assessmentRecord{
		SchemaVersion:   1,
		ChecklistSHA256: sha256Hex(body),
		MappingMethod:   "numeric V/SV mapping from explicit source vulnerability V references or legacy STIG SV references; semantic check equivalence not independently verified",
		Scan:            evidenceInput{scanPath, report.ScanSHA256},
		Benchmark:       evidenceInput{benchmarkPath, report.BenchmarkSHA256},
		Reconciliation:  report,
	}
	if htmlPath != "" {
		record.HTML = &evidenceInput{htmlPath, sha256Hex(html)}
	}
	if arfPath != "" {
		record.ARF = &evidenceInput{arfPath, sha256Hex(arf)}
	}
	if len(tailoring) == 1 {
		record.Tailoring = tailoring[0]
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
