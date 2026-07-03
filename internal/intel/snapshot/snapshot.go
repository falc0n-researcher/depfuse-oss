// Package snapshot embeds a slim, weaponized-only npm advisory index into the
// depfuse binary so a first-time user can run `scan --offline` without first
// downloading the full ~200 MB OSV export via `collect`. The embedded snapshot
// is built by cmd/build-snapshot from a full collect and contains exactly the
// advisories Depfuse would not classify Quiet (KEV / Nuclei / Metasploit /
// Exploit-DB / public PoC / EPSS >= 0.05).
package snapshot

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed slim.db
var slimDB []byte

// Available reports whether a non-empty snapshot was compiled into the binary.
func Available() bool { return len(slimDB) > 0 }

// Size returns the embedded snapshot size in bytes.
func Size() int { return len(slimDB) }

// Extract writes the embedded snapshot to dest (creating parent directories) and
// reports whether it wrote a file. It never overwrites an existing file and
// no-ops when no snapshot is embedded, so callers can invoke it unconditionally
// before opening the default database.
func Extract(dest string) (bool, error) {
	if len(slimDB) == 0 {
		return false, nil
	}
	if _, err := os.Stat(dest); err == nil {
		return false, nil // already present — never clobber a user/collect DB
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return false, err
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, slimDB, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}
