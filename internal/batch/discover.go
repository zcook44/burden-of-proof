// Package batch discovers owner-private OpenSCAP scan bundles recursively.
// A bundle is one ordinary XCCDF result and the same-prefix HTML report;
// ARF/OVAL evidence is optional. No files are modified by discovery.
package batch

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type Scan struct{ Dir, Prefix, XCCDF, HTML, ARF string }

func privateDirectory(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode().Perm()&0077 != 0 || owner.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("directory must be owner-private and not a symlink: %s", path)
	}
	return nil
}

// Discover rejects symlinks, public directories, ambiguous XCCDF names, and
// missing HTML. The path is provided by the caller, never hard-coded.
func Discover(root string) ([]Scan, error) {
	if err := privateDirectory(root); err != nil {
		return nil, err
	}
	found := map[string]*Scan{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in scan tree: %s", path)
		}
		if entry.IsDir() {
			return privateDirectory(path)
		}
		name := entry.Name()
		kind := ""
		prefix := ""
		for _, pair := range [][2]string{{".results.xccdf.xml", "xccdf"}, {".results.xml", "xccdf"}, {".report.html", "html"}, {".results.arf.xml", "arf"}} {
			if strings.HasSuffix(name, pair[0]) {
				prefix = strings.TrimSuffix(name, pair[0])
				kind = pair[1]
				break
			}
		}
		if kind == "" {
			return nil
		}
		if prefix == "" || prefix == "." || prefix == ".." {
			return fmt.Errorf("invalid scan prefix in %s", path)
		}
		key := filepath.Join(filepath.Dir(path), prefix)
		if found[key] == nil {
			found[key] = &Scan{Dir: filepath.Dir(path), Prefix: prefix}
		}
		v := found[key]
		switch kind {
		case "xccdf":
			if v.XCCDF != "" {
				return fmt.Errorf("ambiguous XCCDF for %s", key)
			}
			v.XCCDF = path
		case "html":
			if v.HTML != "" {
				return fmt.Errorf("ambiguous HTML for %s", key)
			}
			v.HTML = path
		case "arf":
			if v.ARF != "" {
				return fmt.Errorf("ambiguous ARF for %s", key)
			}
			v.ARF = path
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("no OpenSCAP scan bundles beneath %s", root)
	}
	scans := make([]Scan, 0, len(found))
	for key, v := range found {
		if v.XCCDF == "" || v.HTML == "" {
			return nil, fmt.Errorf("incomplete scan bundle %s: XCCDF and same-prefix HTML required", key)
		}
		scans = append(scans, *v)
	}
	sort.Slice(scans, func(i, j int) bool { return scans[i].XCCDF < scans[j].XCCDF })
	return scans, nil
}
