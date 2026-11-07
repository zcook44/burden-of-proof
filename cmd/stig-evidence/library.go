package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/zcook44/burden-of-proof/internal/reconcile"
)

var officialName = regexp.MustCompile(`^U_RHEL_([0-9]+)_STIG_V([0-9]+)R([0-9]+)_Manual-xccdf\.xml$`)
var releaseInfo = regexp.MustCompile(`^Release: ([0-9]+) Benchmark Date: .+$`)

type libraryBenchmark struct {
	XMLName xml.Name `xml:"Benchmark"`
	ID      string   `xml:"id,attr"`
	Version string   `xml:"version"`
	Plain   []struct {
		ID   string `xml:"id,attr"`
		Text string `xml:",chardata"`
	} `xml:"plain-text"`
}

func privateLibraryDirectory(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode().Perm()&0077 != 0 || owner.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("library directory must be owner-private and not a symlink: %s", path)
	}
	return nil
}

// latestBenchmark selects the highest official V/R tuple for the source OS.
// SSG result version is not a DISA release number.
func latestBenchmark(root string, scan []byte) (string, []byte, error) {
	major, err := reconcile.SourceFamily(scan)
	if err != nil {
		return "", nil, err
	}
	if err := privateLibraryDirectory(root); err != nil {
		return "", nil, err
	}
	selected := ""
	var selectedData []byte
	bestV, bestR := 0, 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in benchmark library: %s", path)
		}
		if entry.IsDir() {
			return privateLibraryDirectory(path)
		}
		name := entry.Name()
		if !strings.HasPrefix(name, fmt.Sprintf("U_RHEL_%d_STIG", major)) || !strings.HasSuffix(name, "_Manual-xccdf.xml") {
			return nil
		}
		parts := officialName.FindStringSubmatch(name)
		if parts == nil {
			return fmt.Errorf("invalid RHEL %d benchmark filename: %s", major, path)
		}
		family, _ := strconv.Atoi(parts[1])
		v, _ := strconv.Atoi(parts[2])
		r, _ := strconv.Atoi(parts[3])
		if family != major || v < 1 || r < 1 {
			return fmt.Errorf("invalid RHEL %d benchmark release: %s", major, path)
		}
		data, err := readPrivate(path)
		if err != nil {
			return fmt.Errorf("benchmark %s: %w", path, err)
		}
		if bytes.Contains(data, []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
			return fmt.Errorf("benchmark %s: DTD/entity forbidden", path)
		}
		var b libraryBenchmark
		if err := xml.Unmarshal(data, &b); err != nil {
			return fmt.Errorf("benchmark %s: %w", path, err)
		}
		version, err := strconv.Atoi(strings.TrimSpace(b.Version))
		if err != nil || b.XMLName.Space != "http://checklists.nist.gov/xccdf/1.1" || b.ID != fmt.Sprintf("RHEL_%d_STIG", major) || version != v {
			return fmt.Errorf("benchmark identity/version mismatch: %s", path)
		}
		release := 0
		count := 0
		for _, p := range b.Plain {
			if p.ID == "release-info" {
				count++
				match := releaseInfo.FindStringSubmatch(strings.TrimSpace(p.Text))
				if match != nil {
					release, _ = strconv.Atoi(match[1])
				}
			}
		}
		if count != 1 || release != r {
			return fmt.Errorf("benchmark release metadata mismatch: %s", path)
		}
		if selected == "" || v > bestV || (v == bestV && r > bestR) {
			selected, selectedData, bestV, bestR = path, data, v, r
		} else if v == bestV && r == bestR {
			return fmt.Errorf("ambiguous benchmark V%dR%d: %s and %s", v, r, selected, path)
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if selected == "" {
		return "", nil, fmt.Errorf("no extracted RHEL %d manual XCCDF benchmark beneath %s", major, root)
	}
	return selected, selectedData, nil
}
