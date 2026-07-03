// Command build-snapshot turns a full intelligence DB (from `depfuse collect`)
// into the slim, weaponized-only snapshot embedded in the depfuse binary and
// shipped as the zero-collect first-run offline index.
//
// Usage:
//
//	depfuse collect --db /tmp/full-intel.db
//	go run ./cmd/build-snapshot -from /tmp/full-intel.db -out internal/intel/snapshot/slim.db
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
)

func main() {
	from := flag.String("from", "", "path to a full intel.db built by `depfuse collect` (required)")
	out := flag.String("out", filepath.Join("internal", "intel", "snapshot", "slim.db"), "path to write the slim snapshot")
	epss := flag.Float64("epss", intel.WeaponizedEPSSThreshold, "keep signal-free advisories with EPSS at/above this score")
	flag.Parse()

	if *from == "" {
		fmt.Fprintln(os.Stderr, "error: -from is required (run `depfuse collect --db <path>` first)")
		os.Exit(2)
	}

	if err := run(*from, *out, *epss); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(from, out string, epss float64) error {
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	// Work on a copy so the source full DB is never mutated. Only the main DB
	// file is copied; WAL/SHM sidecars are checkpointed away by the copy + open.
	if err := copyFile(from, out); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", from, out, err)
	}
	for _, side := range []string{out + "-wal", out + "-shm"} {
		_ = os.Remove(side)
	}

	store, err := intel.Open(out)
	if err != nil {
		return err
	}

	if !store.HasOSVNPM() {
		store.Close()
		return fmt.Errorf("%s has no osv_npm index — was it built by `depfuse collect`?", from)
	}

	st, err := store.PruneToWeaponized(epss)
	if err != nil {
		store.Close()
		return err
	}
	// Close before measuring so the WAL is checkpointed into the main file.
	if err := store.Close(); err != nil {
		return err
	}
	for _, side := range []string{out + "-wal", out + "-shm"} {
		_ = os.Remove(side)
	}

	size := fileSize(out)
	fmt.Printf("slim snapshot written: %s\n", out)
	fmt.Printf("  weaponized advisories: %d\n", st.AdvisoriesKept)
	fmt.Printf("  vulnerabilities kept:  %d\n", st.VulnsKept)
	fmt.Printf("  size:                  %.1f MB (EPSS >= %g)\n", float64(size)/(1<<20), epss)
	if st.AdvisoriesKept == 0 {
		return fmt.Errorf("refusing to ship an empty snapshot")
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	w, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}
