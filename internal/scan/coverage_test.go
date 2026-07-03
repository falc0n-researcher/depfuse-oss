package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/scan"
	"github.com/falc0n-researcher/depfuse-oss/internal/testdata"
	"github.com/stretchr/testify/require"
)

func TestScanFailsOnIncompleteCoverageWithoutCIFlag(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{
  "name": "no-lock",
  "dependencies": { "lodash": "^4.17.0" }
}`), 0o644))

	runner := &scan.Runner{}
	_, code, err := runner.Run(context.Background(), scan.Options{
		Path:     dir,
		Offline:  true,
		Quiet:    true,
		SkipEmit: true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, code, "incomplete coverage must exit 1 even without --ci")
}

func TestCompleteCoverageWithLockfile(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, testdata.DemoFixtureRoot)
	dbPath := filepath.Join(t.TempDir(), "intel.db")
	require.NoError(t, testdata.SeedIntelDB(dbPath, fixture))

	runner := &scan.Runner{}
	result, code, err := runner.Run(context.Background(), scan.Options{
		Path:     fixture,
		Offline:  true,
		DBPath:   dbPath,
		Quiet:    true,
		SkipEmit: true,
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	require.NotNil(t, result.Meta.Coverage)
	require.Equal(t, "complete", result.Meta.Coverage.Status)
}
