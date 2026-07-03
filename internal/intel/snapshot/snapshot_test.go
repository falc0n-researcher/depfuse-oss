package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtract(t *testing.T) {
	if !Available() {
		t.Fatal("no snapshot embedded — run `make snapshot` to build internal/intel/snapshot/slim.db")
	}

	dest := filepath.Join(t.TempDir(), "nested", "intel.db")

	wrote, err := Extract(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("Extract reported no write on a fresh path")
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("extracted file missing: %v", err)
	}
	if fi.Size() != int64(Size()) {
		t.Errorf("extracted size %d, want %d", fi.Size(), Size())
	}

	// Second call must not clobber an existing database.
	wrote, err = Extract(dest)
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Error("Extract overwrote an existing file")
	}
}
