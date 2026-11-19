package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zcook44/burden-of-proof/internal/config"
	"github.com/zcook44/burden-of-proof/internal/tailoring"
)

func runTailoringRehash(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("tailoring rehash", flag.ContinueOnError)
	flags.SetOutput(stderr)
	libraryRoot := flags.String("library-root", "", "STIG library root whose root tailoring pins are rewritten")
	dryRun := flags.Bool("dry-run", false, "print pin changes without writing")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "tailoring rehash: %v\n", err)
		return 2
	}
	*libraryRoot = config.Resolve(*libraryRoot, "DOCKET_LIBRARY_ROOT", cfg.LibraryRoot, "")
	if flags.NArg() != 0 || *libraryRoot == "" {
		fmt.Fprintln(stderr, "usage: docket tailoring rehash --library-root DIR [--dry-run]")
		return 2
	}
	absolute, err := filepath.Abs(*libraryRoot)
	if err != nil {
		fmt.Fprintf(stderr, "tailoring rehash: %v\n", err)
		return 2
	}
	*libraryRoot = absolute
	entries, err := os.ReadDir(*libraryRoot)
	if err != nil {
		fmt.Fprintf(stderr, "tailoring rehash: %v\n", err)
		return 2
	}
	changed, unchanged := 0, 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tailoring.yaml") {
			continue
		}
		path := filepath.Join(*libraryRoot, entry.Name())
		benchmarkID := strings.TrimSuffix(entry.Name(), ".tailoring.yaml")
		data, err := readPrivate(path)
		if err != nil {
			fmt.Fprintf(stderr, "tailoring rehash: %v\n", err)
			return 2
		}
		benchmarkPath, benchmark, err := benchmarkForID(*libraryRoot, benchmarkID)
		if err != nil {
			fmt.Fprintf(stderr, "tailoring rehash: %s: %v\n", entry.Name(), err)
			return 2
		}
		next := tailoring.SHA256Hex(benchmark)
		updated, didChange, err := tailoring.RewriteRootHash(data, next)
		if err != nil {
			fmt.Fprintf(stderr, "tailoring rehash: %s: %v\n", entry.Name(), err)
			return 2
		}
		if !didChange {
			fmt.Fprintf(out, "UNCHANGED %s (%s)\n", path, benchmarkPath)
			unchanged++
			continue
		}
		fmt.Fprintf(out, "REHASH %s -> %s (%s)\n", path, next, benchmarkPath)
		changed++
		if *dryRun {
			continue
		}
		if err := writePrivateReplace(path, updated); err != nil {
			fmt.Fprintf(stderr, "tailoring rehash: %s: %v\n", path, err)
			return 2
		}
	}
	if *dryRun {
		fmt.Fprintf(out, "DRY RUN rehash changed=%d unchanged=%d\n", changed, unchanged)
	} else {
		fmt.Fprintf(out, "REHASH changed=%d unchanged=%d\n", changed, unchanged)
	}
	return 0
}

func runTailoringMigrate(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("tailoring migrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	libraryRoot := flags.String("library-root", "", "library root whose root tailoring files are migrated")
	scanRoot := flags.String("scan-root", "", "optional tree of host tailoring files")
	dryRun := flags.Bool("dry-run", false, "print migrations without writing")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "tailoring migrate: %v\n", err)
		return 2
	}
	*libraryRoot = config.Resolve(*libraryRoot, "DOCKET_LIBRARY_ROOT", cfg.LibraryRoot, "")
	scanFromFlag := *scanRoot != ""
	*scanRoot = config.Resolve(*scanRoot, "DOCKET_INPUT_ROOT", cfg.InputRoot, "")
	if *scanRoot != "" && !scanFromFlag {
		if st, statErr := os.Stat(*scanRoot); statErr != nil || !st.IsDir() {
			fmt.Fprintf(stderr, "tailoring migrate: scan root %s is not a directory yet; host files not migrated\n", *scanRoot)
			*scanRoot = ""
		}
	}
	if flags.NArg() != 0 || *libraryRoot == "" {
		fmt.Fprintln(stderr, "usage: docket tailoring migrate --library-root DIR [--scan-root DIR] [--dry-run]")
		return 2
	}
	for _, path := range []*string{libraryRoot, scanRoot} {
		if *path == "" {
			continue
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			fmt.Fprintf(stderr, "tailoring migrate: %v\n", err)
			return 2
		}
		*path = absolute
	}
	rewritten := 0
	migrateOne := func(path string, layer tailoring.Layer) error {
		benchmarkID := strings.TrimSuffix(filepath.Base(path), ".tailoring.yaml")
		data, err := readPrivate(path)
		if err != nil {
			return err
		}
		next, err := tailoring.Migrate(data, layer, benchmarkID)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if string(next) == string(data) {
			fmt.Fprintf(out, "UNCHANGED %s\n", path)
			return nil
		}
		fmt.Fprintf(out, "MIGRATE %s (%s)\n", path, layer)
		rewritten++
		if *dryRun {
			return nil
		}
		return writePrivateReplace(path, next)
	}
	entries, err := os.ReadDir(*libraryRoot)
	if err != nil {
		fmt.Fprintf(stderr, "tailoring migrate: %v\n", err)
		return 2
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tailoring.yaml") {
			continue
		}
		if err := migrateOne(filepath.Join(*libraryRoot, entry.Name()), tailoring.Root); err != nil {
			fmt.Fprintf(stderr, "tailoring migrate: %v\n", err)
			return 2
		}
	}
	if *scanRoot != "" {
		err = filepath.WalkDir(*scanRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tailoring.yaml") {
				return nil
			}
			return migrateOne(path, tailoring.Host)
		})
		if err != nil {
			fmt.Fprintf(stderr, "tailoring migrate: %v\n", err)
			return 2
		}
	}
	if *dryRun {
		fmt.Fprintf(out, "DRY RUN migrate files=%d\n", rewritten)
	} else {
		fmt.Fprintf(out, "MIGRATE files=%d\n", rewritten)
	}
	return 0
}

func writePrivateReplace(path string, body []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		os.Remove(tmp)
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		os.Remove(tmp)
		return fmt.Errorf("%s is a symlink", path)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Chmod(path, 0600)
}
