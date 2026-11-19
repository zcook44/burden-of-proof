// Package tailoring is the single schema for docket and checkmate tailoring files.
// Schema version 3 is the only format either tool reads. Older files are converted
// with docket tailoring migrate; they are not accepted at conversion time.
package tailoring

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const SchemaVersion = 3

type Layer string

const (
	Root Layer = "root"
	Host Layer = "host"
)

var ruleNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Rule is one partial-inventory row.
// Origin is set by Merge and is not stored in the file.
type Rule struct {
	RuleName string `yaml:"rule_name,omitempty"`
	STIGID   string `yaml:"stig_id"`
	SVID     string `yaml:"sv_id"`
	Status   string `yaml:"status"`
	Comment  string `yaml:"comment,omitempty"`
	Origin   string `yaml:"-"`
}

// File is a schema v3 tailoring document.
// BenchmarkSHA256 is required on the root file and forbidden on a host file.
// Host files inherit the root pin and the benchmark id of the file they override.
type File struct {
	SchemaVersion   int    `yaml:"schema_version"`
	BenchmarkID     string `yaml:"benchmark_id"`
	BenchmarkSHA256 string `yaml:"benchmark_sha256,omitempty"`
	Rules           []Rule `yaml:"rules"`
	Layer           Layer  `yaml:"-"`
}

// SHA256Hex is the lowercase hex digest stored in a root tailoring file.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Parse validates schema v3. controls maps a STIG group id to its official rule id.
// benchmarkSHA is the digest of the benchmark bytes selected for this run.
// It is compared only for the root layer.
func Parse(data []byte, layer Layer, path, benchmarkID, benchmarkSHA string, controls map[string]string) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var policy File
	if err := dec.Decode(&policy); err != nil {
		return nil, fmt.Errorf("%s tailoring %s: %w", layer, path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("%s tailoring %s: only one YAML document is allowed", layer, path)
	}
	if policy.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%s tailoring %s: schema_version %d is not current (want %d); run: docket tailoring migrate", layer, path, policy.SchemaVersion, SchemaVersion)
	}
	if policy.BenchmarkID != benchmarkID {
		return nil, fmt.Errorf("%s tailoring %s: benchmark_id mismatch (expected %s, got %s)", layer, path, benchmarkID, policy.BenchmarkID)
	}
	if policy.Rules == nil {
		return nil, fmt.Errorf("%s tailoring %s: rules must be a YAML list (use [] for none)", layer, path)
	}
	switch layer {
	case Root:
		if !hexHash.MatchString(policy.BenchmarkSHA256) {
			return nil, fmt.Errorf("%s tailoring %s: benchmark_sha256 must be the SHA-256 of the benchmark; run: docket tailoring rehash --library-root <library>", layer, path)
		}
		if policy.BenchmarkSHA256 != benchmarkSHA {
			return nil, fmt.Errorf("%s tailoring %s: benchmark_sha256 mismatch (file %s, benchmark %s); run: docket tailoring rehash --library-root <library>", layer, path, policy.BenchmarkSHA256, benchmarkSHA)
		}
	case Host:
		if policy.BenchmarkSHA256 != "" {
			return nil, fmt.Errorf("%s tailoring %s: benchmark_sha256 belongs only on the root tailoring file; delete it and run: docket tailoring migrate", layer, path)
		}
	default:
		return nil, fmt.Errorf("unknown tailoring layer %q", layer)
	}
	seen := map[string]bool{}
	for i := range policy.Rules {
		rule := &policy.Rules[i]
		if rule.STIGID == "" || seen[rule.STIGID] {
			return nil, fmt.Errorf("%s tailoring %s: missing or duplicate STIG ID %q", layer, path, rule.STIGID)
		}
		seen[rule.STIGID] = true
		if controls[rule.STIGID] != rule.SVID {
			return nil, fmt.Errorf("%s tailoring %s: unknown or mismatched STIG/SV ID %q / %q", layer, path, rule.STIGID, rule.SVID)
		}
		if rule.RuleName != "" && !ruleNamePattern.MatchString(rule.RuleName) {
			return nil, fmt.Errorf("%s tailoring %s: invalid rule_name %q for %s", layer, path, rule.RuleName, rule.STIGID)
		}
		switch rule.Status {
		case "auto", "open", "not_a_finding", "not_applicable", "not_reviewed":
		default:
			return nil, fmt.Errorf("%s tailoring %s: invalid status %q for %s", layer, path, rule.Status, rule.STIGID)
		}
		comment := strings.TrimSpace(rule.Comment)
		if rule.Status != "auto" && comment == "" {
			return nil, fmt.Errorf("%s tailoring %s: comment required for non-auto status on %s", layer, path, rule.STIGID)
		}
		if layer == Host && rule.Status == "auto" && comment == "" {
			return nil, fmt.Errorf("%s tailoring %s: comment required for host auto on %s (say why the root decision does not apply)", layer, path, rule.STIGID)
		}
	}
	policy.Layer = layer
	return &policy, nil
}

// Merge applies root rules first. A host rule with the same stig_id replaces the root rule.
func Merge(root, host []Rule) []Rule {
	order := make([]string, 0, len(root)+len(host))
	merged := map[string]Rule{}
	for _, rule := range root {
		rule.Origin = string(Root)
		if _, ok := merged[rule.STIGID]; !ok {
			order = append(order, rule.STIGID)
		}
		merged[rule.STIGID] = rule
	}
	for _, rule := range host {
		rule.Origin = string(Host)
		if _, ok := merged[rule.STIGID]; !ok {
			order = append(order, rule.STIGID)
		}
		merged[rule.STIGID] = rule
	}
	out := make([]Rule, 0, len(order))
	for _, id := range order {
		out = append(out, merged[id])
	}
	return out
}

// Format renders a schema v3 file. The root layer includes benchmark_sha256.
// The host layer does not. rule_name is omitted when empty.
func Format(f File) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "schema_version: %d\n", SchemaVersion)
	fmt.Fprintf(&b, "benchmark_id: %s\n", f.BenchmarkID)
	if f.Layer != Host {
		hash := f.BenchmarkSHA256
		if hash == "" {
			hash = "rehash-me"
		}
		fmt.Fprintf(&b, "benchmark_sha256: %s\n", hash)
	}
	if len(f.Rules) == 0 {
		b.WriteString("rules: []\n")
		return []byte(b.String())
	}
	b.WriteString("rules:\n")
	for _, rule := range f.Rules {
		b.WriteString("  - stig_id: " + rule.STIGID + "\n")
		b.WriteString("    sv_id: " + rule.SVID + "\n")
		if rule.RuleName != "" {
			b.WriteString("    rule_name: " + rule.RuleName + "\n")
		}
		b.WriteString("    status: " + rule.Status + "\n")
		if strings.TrimSpace(rule.Comment) != "" {
			b.WriteString("    comment: " + quoteYAML(rule.Comment) + "\n")
		}
	}
	return []byte(b.String())
}

func quoteYAML(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
