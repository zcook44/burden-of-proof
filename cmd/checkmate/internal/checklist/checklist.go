// Package checklist discovers and safely edits STIG Viewer CKLB files.
package checklist

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var statuses = map[string]bool{"open": true, "not_reviewed": true, "not_a_finding": true, "not_applicable": true}

// Rule describes one checklist row. StigIndex/RuleIndex locate it in its original file.
type Rule struct {
	Benchmark, Release, ID, RuleID, Title, Severity, Status, Comment, Findings, Check string
	StigIndex, RuleIndex                                                              int
}
type File struct {
	Path   string
	Rules  []Rule
	Data   []byte
	Digest [32]byte
}

func (r Rule) Key() string {
	return r.Benchmark + "\x00" + r.Release + "\x00" + r.ID + "\x00" + r.RuleID
}
func text(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func parse(path string, data []byte) (File, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	stigs, ok := doc["stigs"].([]any)
	if !ok || len(stigs) == 0 {
		return File{}, fmt.Errorf("%s: no STIGs", path)
	}
	f := File{Path: path, Data: data, Digest: sha256.Sum256(data)}
	seen := map[string]bool{}
	for si, raw := range stigs {
		stig, ok := raw.(map[string]any)
		if !ok {
			return File{}, fmt.Errorf("%s: invalid STIG", path)
		}
		rules, ok := stig["rules"].([]any)
		if !ok {
			return File{}, fmt.Errorf("%s: STIG has no rules", path)
		}
		benchmark := text(stig, "stig_id")
		if benchmark == "" {
			return File{}, fmt.Errorf("%s: missing benchmark ID", path)
		}
		for ri, value := range rules {
			row, ok := value.(map[string]any)
			if !ok {
				return File{}, fmt.Errorf("%s: invalid rule", path)
			}
			r := Rule{Benchmark: benchmark, Release: text(stig, "release_info"), ID: text(row, "group_id"), RuleID: text(row, "rule_id"), Title: text(row, "rule_title"), Severity: text(row, "severity"), Status: text(row, "status"), Comment: text(row, "comments"), Findings: text(row, "finding_details"), Check: text(row, "check_content"), StigIndex: si, RuleIndex: ri}
			if r.ID == "" || r.RuleID == "" || !statuses[r.Status] {
				return File{}, fmt.Errorf("%s: missing ID or unsupported status at STIG %d rule %d", path, si, ri)
			}
			if seen[r.Key()] {
				return File{}, fmt.Errorf("%s: duplicate control %s / %s", path, r.ID, r.RuleID)
			}
			seen[r.Key()] = true
			f.Rules = append(f.Rules, r)
		}
	}
	return f, nil
}
func regular(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file (symlinks prohibited)", path)
	}
	return info, nil
}
func Load(path string) (File, error) {
	if _, err := regular(path); err != nil {
		return File{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	return parse(path, data)
}

// Preflight verifies the selected bytes and the ability to stage a replacement.
// Edit repeats the hash check immediately before writing.
func Preflight(f File, schema *Schema) error {
	if _, err := regular(f.Path); err != nil {
		return err
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	if sha256.Sum256(data) != f.Digest {
		return fmt.Errorf("%s: checklist changed since load", f.Path)
	}
	if schema != nil {
		if err := schema.Validate(data); err != nil {
			return fmt.Errorf("%s: %w", f.Path, err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".checkmate-preflight-*")
	if err != nil {
		return fmt.Errorf("%s: cannot stage replacement: %w", f.Path, err)
	}
	name := tmp.Name()
	closeErr := tmp.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}

type candidate struct {
	path  string
	stamp int64
	tie   string
}

// Discover selects the most recently modified CKLB in each directory; ties fail closed.
func Discover(root string) ([]File, error) {
	return discover(root, "")
}

// DiscoverBenchmark keeps, in each directory, the newest CKLB that contains benchmark.
// benchmark is the CKLB stig_id, matched exactly. Rules from any other benchmark in that
// file are omitted. An empty benchmark is Discover.
func DiscoverBenchmark(root, benchmark string) ([]File, error) {
	return discover(root, strings.TrimSpace(benchmark))
}
func discover(root, benchmark string) ([]File, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s: root must be a directory", root)
	}
	latest := map[string]candidate{}
	present := map[string]bool{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlink in checklist tree", p)
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".cklb") {
			return nil
		}
		stat, err := regular(p)
		if err != nil {
			return err
		}
		if benchmark != "" {
			ids, err := stigIDs(p)
			if err != nil {
				return err
			}
			matched := false
			for _, id := range ids {
				if id == "" {
					continue
				}
				present[id] = true
				if id == benchmark {
					matched = true
				}
			}
			if !matched {
				return nil
			}
		}
		dir := filepath.Dir(p)
		stamp := stat.ModTime().UnixNano()
		prev, ok := latest[dir]
		if ok && prev.stamp == stamp {
			prev.tie = p
			latest[dir] = prev
			return nil
		}
		if ok && prev.stamp > stamp {
			return nil
		}
		latest[dir] = candidate{path: p, stamp: stamp}
		return nil
	})
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(latest))
	for dir, item := range latest {
		if item.tie != "" {
			if benchmark != "" {
				return nil, fmt.Errorf("%s: newest CKLB timestamp tie for benchmark %q (%s and %s)", dir, benchmark, item.path, item.tie)
			}
			return nil, fmt.Errorf("%s: newest CKLB timestamp tie (%s and %s)", dir, item.path, item.tie)
		}
		paths = append(paths, item.path)
	}
	sort.Strings(paths)
	files := make([]File, 0, len(paths))
	for _, p := range paths {
		f, err := Load(p)
		if err != nil {
			return nil, err
		}
		if benchmark != "" {
			kept := make([]Rule, 0, len(f.Rules))
			for _, rule := range f.Rules {
				if rule.Benchmark == benchmark {
					kept = append(kept, rule)
				}
			}
			f.Rules = kept
			if len(f.Rules) == 0 {
				continue
			}
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		if benchmark != "" {
			return nil, fmt.Errorf("no CKLB contains benchmark %q%s", benchmark, presentList(present))
		}
		return nil, errors.New("no CKLB files found")
	}
	return files, nil
}
func stigIDs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Stigs []struct {
			ID string `json:"stig_id"`
		} `json:"stigs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(doc.Stigs) == 0 {
		return nil, fmt.Errorf("%s: no STIGs", path)
	}
	ids := make([]string, len(doc.Stigs))
	for i, stig := range doc.Stigs {
		ids[i] = stig.ID
	}
	return ids, nil
}
func presentList(ids map[string]bool) string {
	if len(ids) == 0 {
		return ""
	}
	names := make([]string, 0, len(ids))
	for id := range ids {
		names = append(names, id)
	}
	sort.Strings(names)
	return " (present: " + strings.Join(names, ", ") + ")"
}

// Edit replaces exactly one rule's status and comment in its selected checklist.
// A changed file is refused; a temporary sibling is fsynced and renamed over it.
func Edit(f File, index int, status, comment string) error {
	if !statuses[status] {
		return fmt.Errorf("invalid CKLB status %q", status)
	}
	if strings.TrimSpace(comment) == "" {
		return errors.New("comment must not be empty")
	}
	if index < 0 || index >= len(f.Rules) {
		return errors.New("rule index out of bounds")
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	if sha256.Sum256(data) != f.Digest {
		return fmt.Errorf("%s: checklist changed since load", f.Path)
	}
	info, err := regular(f.Path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	r := f.Rules[index]
	row := doc["stigs"].([]any)[r.StigIndex].(map[string]any)["rules"].([]any)[r.RuleIndex].(map[string]any)
	if text(row, "group_id") != r.ID || text(row, "rule_id") != r.RuleID {
		return errors.New("selected rule identity changed")
	}
	row["status"], row["comments"] = status, comment
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	updated = append(updated, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".checkmate-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err = tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err = tmp.Write(updated); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	current, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	if sha256.Sum256(current) != f.Digest {
		return fmt.Errorf("%s: checklist changed during edit", f.Path)
	}
	if _, err = regular(f.Path); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), f.Path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(f.Path))
	if err == nil {
		defer dir.Close()
		if err = dir.Sync(); err != nil {
			return fmt.Errorf("rename succeeded but directory sync failed: %w", err)
		}
	}
	return nil
}
func Same(a, b []byte) bool { return bytes.Equal(a, b) }
