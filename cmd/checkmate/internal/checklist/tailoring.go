package checklist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zcook44/burden-of-proof/internal/tailoring"
)

// TailoringEntry is one rule in a docket tailoring file.
// rule_name is optional and is not invented from CKLB JSON.
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
			if onlyNonDefault && !tailoring.IsAdminDecision(p.status, p.comment) {
				continue
			}
			tf.Entries = append(tf.Entries, TailoringEntry{
				StigID:  rk.id,
				SvID:    rk.ruleID,
				Status:  p.status,
				Comment: p.comment,
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

// FormatTailoringYAML renders a schema v3 root candidate.
// It has no benchmark hash and no rule_name. Install it at the library root
// and run docket tailoring rehash before conversion.
func FormatTailoringYAML(tf TailoringFile) string {
	f := tailoring.File{
		SchemaVersion:   tailoring.SchemaVersion,
		BenchmarkID:     tf.Benchmark,
		BenchmarkSHA256: "",
		Layer:           tailoring.Root,
	}
	for _, e := range tf.Entries {
		f.Rules = append(f.Rules, tailoring.Rule{
			STIGID: e.StigID, SVID: e.SvID, Status: e.Status, Comment: e.Comment,
		})
	}
	if f.Rules == nil {
		f.Rules = []tailoring.Rule{}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s tailoring candidate from checkmate --export-tailoring.\n", tf.Benchmark)
	fmt.Fprintf(&b, "# %s\n", tf.Release)
	fmt.Fprintf(&b, "# Schema version 3. benchmark_sha256 is filled by: docket tailoring rehash --library-root <library>\n")
	fmt.Fprintf(&b, "# Rows are administrator decisions shared by every selected host. Plain scan passes are omitted.\n")
	fmt.Fprintf(&b, "# An explicit status replaces the next scan for every %s host that uses this root file.\n", tf.Benchmark)
	b.Write(tailoring.Format(f))
	return b.String()
}
