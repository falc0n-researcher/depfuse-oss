package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli"
	"github.com/stretchr/testify/require"
)

func TestDoctorCIFailsWithoutPinnedIntel(t *testing.T) {
	root := cli.NewRoot()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	t.Setenv("DEPFUSE_INTEL_DB", "")
	t.Setenv("DEPFUSE_SKIP_AUTO_COLLECT", "")
	root.SetArgs([]string{"doctor", "--ci"})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, buf.String(), "DEPFUSE_INTEL_DB not set")
}

func TestDoctorCIPassesWithPinnedIntel(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "intel.db")
	require.NoError(t, os.WriteFile(db, []byte("sqlite"), 0o644))

	root := cli.NewRoot()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	t.Setenv("DEPFUSE_INTEL_DB", db)
	t.Setenv("DEPFUSE_SKIP_AUTO_COLLECT", "1")
	root.SetArgs([]string{"doctor", "--ci"})
	require.NoError(t, root.Execute())
	require.Contains(t, buf.String(), "deterministic")
}
