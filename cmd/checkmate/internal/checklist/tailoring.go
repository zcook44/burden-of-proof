package checklist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TailoringEntry is one rule in a docket tailoring file.
// RuleName is not stored in CKLB JSON; exports leave it as PLACEHOLDER.
type TailoringEntry struct {
	RuleName string
	StigID   string
	SvID     string
	Status   string
	Comment  string
}

// TailoringFile is the agreed rows for one benchmark release.
type TailoringFile struct {
	Benchmark string
	Release   string
	Entries   []TailoringEntry
}

// WrittenTailoring is one file produced by WriteTailoringExports.
type WrittenTailoring struct {
	Path      string
	Benchmark string
	Release   string
	Count     int
}

// AnalyzeTailoring keeps a rule only when every checklist that contains that
// benchmark and release recorded the same status and comment. A file contributes
// to the host count for each benchmark it actually contains, not merely its first rule.
// onlyNonDefault drops not_reviewed rows whose comment is empty or still says NOT REVIEWED.
func AnalyzeTailoring(files []File, onlyNonDefault bool) []TailoringFile {
	type key struct {
		benchmark, release string
	}
	type ruleKey struct {
		id, ruleID string
	}
	type pattern struct {
		status  string
		comment string
		count   int
	}

	benchmarks := make(map[key]map[ruleKey]pattern)
	for _, f := range files {
		for _, r := range f.Rules {
			k := key{r.Benchmark, r.Release}
			if benchmarks[k] == nil {
				benchmarks[k] = make(map[ruleKey]pattern)
			}
			rk := ruleKey{r.ID, r.RuleID}
			p := benchmarks[k][rk]
			if p.count == 0 {
				p.status = r.Status
				p.comment = r.Comment
				p.count = 1
			} else if p.status == r.Status && p.comment == r.Comment {
				p.count++
			} else {
				p.count = -1
			}
			benchmarks[k][rk] = p
		}
	}

	hostCounts := make(map[key]int)
	for _, f := range files {
		seen := map[key]bool{}
		for _, r := range f.Rules {
			k := key{r.Benchmark, r.Release}
			if seen[k] {
				continue
			}
			seen[k] = true
			hostCounts[k]++
		}
	}

	var results []TailoringFile
	for bk, rules := range benchmarks {
		tf := TailoringFile{Benchmark: bk.benchmark, Release: bk.release}
		for rk, p := range rules {
			if p.count != hostCounts[bk] || p.count <= 0 {
				continue
			}
			if onlyNonDefault && p.status == "not_reviewed" &&
				(strings.TrimSpace(p.comment) == "" || strings.Contains(p.comment, "NOT REVIEWED")) {
				continue
			}
			tf.Entries = append(tf.Entries, TailoringEntry{
				RuleName: "PLACEHOLDER",
				StigID:   rk.id,
				SvID:     rk.ruleID,
				Status:   p.status,
				Comment:  p.comment,
			})
		}
		sort.Slice(tf.Entries, func(i, j int) bool {
			return tf.Entries[i].StigID < tf.Entries[j].StigID
		})
		if len(tf.Entries) > 0 {
			results = append(results, tf)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Benchmark != results[j].Benchmark {
			return results[i].Benchmark < results[j].Benchmark
		}
		return results[i].Release < results[j].Release
	})
	return results
}

// WriteTailoringExports creates dir if needed and writes one new tailoring file per benchmark.
// It refuses a symlink, an existing file, a benchmark id that is not a single path element,
// and two releases of the same benchmark. Docket expects one library file per stig_id.
func WriteTailoringExports(dir string, sets []TailoringFile) ([]WrittenTailoring, error) {
	if len(sets) == 0 {
		return nil, errors.New("no agreed rules to export: every selected host must share a status and comment, and untouched not_reviewed rows are omitted")
	}
	info, err := os.Lstat(dir)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return nil, fmt.Errorf("%s: refusing to write through a symlink", dir)
	case err == nil && !info.IsDir():
		return nil, fmt.Errorf("%s: export path must be a directory", dir)
	case err == nil:
	case os.IsNotExist(err):
		if err = os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	releases := map[string]string{}
	paths := make([]string, len(sets))
	for i, tf := range sets {
		name, err := tailoringFilename(tf.Benchmark)
		if err != nil {
			return nil, err
		}
		if prev, ok := releases[tf.Benchmark]; ok {
			return nil, fmt.Errorf("%s: multiple releases (%q and %q); refusing to collapse them into one tailoring file", tf.Benchmark, prev, tf.Release)
		}
		releases[tf.Benchmark] = tf.Release
		paths[i] = filepath.Join(dir, name)
		if _, err := os.Lstat(paths[i]); err == nil {
			return nil, fmt.Errorf("%s: refusing to overwrite an existing tailoring file", paths[i])
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	written := make([]WrittenTailoring, 0, len(sets))
	for i, tf := range sets {
		f, err := os.OpenFile(paths[i], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return written, err
		}
		_, werr := f.WriteString(FormatTailoringYAML(tf))
		cerr := f.Close()
		if werr != nil {
			return written, werr
		}
		if cerr != nil {
			return written, cerr
		}
		written = append(written, WrittenTailoring{Path: paths[i], Benchmark: tf.Benchmark, Release: tf.Release, Count: len(tf.Entries)})
	}
	return written, nil
}

func tailoringFilename(benchmark string) (string, error) {
	if benchmark == "" || benchmark != filepath.Base(benchmark) || strings.Contains(benchmark, "..") {
		return "", fmt.Errorf("refusing benchmark id %q as a file name", benchmark)
	}
	return benchmark + ".tailoring.yaml", nil
}

// FormatTailoringYAML renders a docket tailoring file.
// not_reviewed is written as auto so the next scan keeps its candidate status.
// Any other CKLB status is copied and will override that scan.
func FormatTailoringYAML(tf TailoringFile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s tailoring\n", tf.Benchmark)
	fmt.Fprintf(&b, "# %s\n", tf.Release)
	fmt.Fprintf(&b, "#\n")
	fmt.Fprintf(&b, "# IMPORTANT: This file was generated by checkmate --export-tailoring.\n")
	fmt.Fprintf(&b, "# The 'rule_name' fields are placeholders and must be filled in manually.\n")
	fmt.Fprintf(&b, "# rule_name is the SSG (SCAP Security Guide) remediation rule name.\n")
	fmt.Fprintf(&b, "# CKLB JSON does not carry it.\n")
	fmt.Fprintf(&b, "#\n")
	fmt.Fprintf(&b, "# To find rule_name values:\n")
	fmt.Fprintf(&b, "# 1. Check the burden-of-proof/docket converter documentation\n")
	fmt.Fprintf(&b, "# 2. Reference existing tailoring files for similar rules\n")
	fmt.Fprintf(&b, "# 3. Consult SSG content for your OS version\n")
	fmt.Fprintf(&b, "# From a source checkout, scripts/map-tailoring-rule-names.sh reports\n")
	fmt.Fprintf(&b, "# names already present in a reference directory. It does not edit this file.\n")
	fmt.Fprintf(&b, "#\n")
	fmt.Fprintf(&b, "# status: auto keeps the scan's candidate status. not_reviewed rows are written as auto.\n")
	fmt.Fprintf(&b, "# An explicit status (open, not_a_finding, not_applicable) replaces the next scan\n")
	fmt.Fprintf(&b, "# for EVERY %s host converted with this library. Delete rows that are only last quarter's result.\n", tf.Benchmark)
	fmt.Fprintf(&b, "rules:\n")
	for _, e := range tf.Entries {
		tailoringStatus := "auto"
		if e.Status != "not_reviewed" {
			tailoringStatus = e.Status
		}
		fmt.Fprintf(&b, "  - rule_name: %s  # TODO: Fill in SSG rule name\n", e.RuleName)
		fmt.Fprintf(&b, "    stig_id: %s\n", e.StigID)
		fmt.Fprintf(&b, "    sv_id: %s\n", e.SvID)
		fmt.Fprintf(&b, "    status: %s\n", tailoringStatus)
		fmt.Fprintf(&b, "    comment: %s\n", yamlQuote(e.Comment))
	}
	return b.String()
}

func yamlQuote(s string) string {
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
