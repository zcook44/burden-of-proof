package tailoring

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// Migrate converts a v0 (implicit), v1, or v2 tailoring file into schema v3.
// Comment-less auto rows are dropped, which turns an all-auto Cisco inventory
// into an empty partial file that still pins the benchmark when layer is root.
// A host file loses benchmark_sha256. A root file keeps a 64-hex pin or is
// marked rehash-me so docket tailoring rehash can fill it.
// Already-current files are rewritten in canonical form.
func Migrate(data []byte, layer Layer, benchmarkID string) ([]byte, error) {
	if layer != Root && layer != Host {
		return nil, fmt.Errorf("unknown tailoring layer %q", layer)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var loose File
	if err := dec.Decode(&loose); err != nil {
		return nil, fmt.Errorf("cannot read tailoring: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("only one YAML document is allowed")
	}
	if loose.Rules == nil {
		loose.Rules = []Rule{}
	}
	if loose.BenchmarkID == "" {
		loose.BenchmarkID = benchmarkID
	}
	if loose.BenchmarkID != benchmarkID {
		return nil, fmt.Errorf("benchmark_id %s does not match filename %s", loose.BenchmarkID, benchmarkID)
	}
	kept := make([]Rule, 0, len(loose.Rules))
	for _, rule := range loose.Rules {
		rule.Comment = strings.TrimSpace(rule.Comment)
		rule.Origin = ""
		if rule.Status == "" {
			rule.Status = "auto"
		}
		if rule.Status == "auto" && rule.Comment == "" {
			continue
		}
		if rule.Status != "auto" && rule.Comment == "" {
			rule.Comment = "Migrated from an older tailoring file; replace this with the administrator justification."
		}
		if layer == Host && rule.Status == "auto" && rule.Comment == "" {
			continue
		}
		kept = append(kept, rule)
	}
	out := File{
		SchemaVersion: SchemaVersion,
		BenchmarkID:   benchmarkID,
		Rules:         kept,
		Layer:         layer,
	}
	if layer == Root {
		if hexHash.MatchString(loose.BenchmarkSHA256) {
			out.BenchmarkSHA256 = loose.BenchmarkSHA256
		} else {
			out.BenchmarkSHA256 = "rehash-me"
		}
	}
	return Format(out), nil
}

// RewriteRootHash sets or replaces benchmark_sha256 in a schema v3 root file.
// Comments outside the hash scalar are preserved by editing the YAML node.
// changed is false when the pin is already the requested digest.
func RewriteRootHash(data []byte, hash string) ([]byte, bool, error) {
	if !hexHash.MatchString(hash) {
		return nil, false, fmt.Errorf("refusing non-digest benchmark pin %q", hash)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, false, fmt.Errorf("tailoring root must be a YAML mapping")
	}
	root := doc.Content[0]
	var version string
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "schema_version" {
			version = root.Content[i+1].Value
		}
	}
	if version != "3" {
		return nil, false, fmt.Errorf("schema_version %s is not current; run: docket tailoring migrate", version)
	}
	changed := false
	found := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "benchmark_sha256" {
			continue
		}
		found = true
		if root.Content[i+1].Value == hash && root.Content[i+1].Tag == "!!str" {
			break
		}
		root.Content[i+1].Kind = yaml.ScalarNode
		root.Content[i+1].Tag = "!!str"
		root.Content[i+1].Value = hash
		root.Content[i+1].Style = 0
		changed = true
		break
	}
	if !found {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "benchmark_sha256"}
		val := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: hash}
		insertAt := len(root.Content)
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == "benchmark_id" {
				insertAt = i + 2
				break
			}
		}
		next := make([]*yaml.Node, 0, len(root.Content)+2)
		next = append(next, root.Content[:insertAt]...)
		next = append(next, key, val)
		next = append(next, root.Content[insertAt:]...)
		root.Content = next
		changed = true
	}
	if !changed {
		return data, false, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, false, err
	}
	if err := enc.Close(); err != nil {
		return nil, false, err
	}
	return buf.Bytes(), true, nil
}
