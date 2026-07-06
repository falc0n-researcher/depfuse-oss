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
	require.Contains(t, buf.String(), "Workflow hardening")
}

func TestDoctorCIFailsOnHighSeverityWorkflowFinding(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "intel.db")
	require.NoError(t, os.WriteFile(db, []byte("sqlite"), 0o644))
	wfDir := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(wfDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(wfDir, "risky.yml"), []byte(`
name: Risky
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`), 0o644))

	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	root := cli.NewRoot()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	t.Setenv("DEPFUSE_INTEL_DB", db)
	t.Setenv("DEPFUSE_SKIP_AUTO_COLLECT", "1")
	root.SetArgs([]string{"doctor", "--ci"})
	require.Error(t, root.Execute())
	require.Contains(t, buf.String(), "pull_request_target")
}
