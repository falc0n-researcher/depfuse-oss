package cli_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli"
	"github.com/stretchr/testify/require"
)

func TestRootHelp(t *testing.T) {
	root := cli.NewRoot()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"--help"})
	require.NoError(t, root.Execute())
	require.Contains(t, buf.String(), "Core commands")
	require.Contains(t, buf.String(), "html")
}

func TestValidateFormatScan(t *testing.T) {
	root := cli.NewRoot()
	root.SetArgs([]string{"scan", "--format", "invalid"})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported --format")
}

func TestDoctorRuns(t *testing.T) {
	root := cli.NewRoot()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	t.Setenv("DEPFUSE_INTEL_DB", t.TempDir()+"/intel.db")
	root.SetArgs([]string{"doctor"})
	require.NoError(t, root.Execute())
	require.Contains(t, buf.String(), "Depfuse doctor")
}

func TestDecisionsRecordRequiresFlags(t *testing.T) {
	root := cli.NewRoot()
	root.SetErr(os.Stderr)
	root.SetArgs([]string{"decisions", "record", "CVE-2025-0001"})
	err := root.Execute()
	require.Error(t, err)
}
