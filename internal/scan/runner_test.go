package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/scan"
	"github.com/falc0n-researcher/depfuse-oss/internal/testdata"
	"github.com/stretchr/testify/require"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func testSnapshot(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	require.NoError(t, testdata.EnsureIntelDB(root))
	dbPath, _ := testdata.DefaultPaths(root)
	return dbPath
}

func testRunner(t *testing.T, dbPath string) *scan.Runner {
	t.Helper()
	store, err := intel.Open(dbPath)
	require.NoError(t, err)
	return &scan.Runner{Store: store}
}

func TestScanExpressAppOffline(t *testing.T) {
	root := repoRoot(t)
	dbPath := testSnapshot(t)

	runner := testRunner(t, dbPath)
	result, code, err := runner.Run(context.Background(), scan.Options{
		Path:    filepath.Join(root, "testdata", "express-app"),
		Offline: true,
		DBPath:  dbPath,
		Format:  "json",
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	require.NotEmpty(t, result.Findings)
	require.Equal(t, 4, result.Meta.ComponentCount)
}

func TestScanCIHold(t *testing.T) {
	root := repoRoot(t)
	dbPath := testSnapshot(t)

	runner := testRunner(t, dbPath)
	_, code, err := runner.Run(context.Background(), scan.Options{
		Path:    filepath.Join(root, "testdata", "noise-app"),
		Offline: true,
		DBPath:  dbPath,
		Format:  "json",
		CI:      true,
		FailOn:  "T0,T1",
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)
}

func TestFalsePositiveCorpus(t *testing.T) {
	root := repoRoot(t)
	dbPath := testSnapshot(t)

	runner := testRunner(t, dbPath)
	result, _, err := runner.Run(context.Background(), scan.Options{
		Path:    filepath.Join(root, "testdata", "express-app"),
		Offline: true,
		DBPath:  dbPath,
		Format:  "json",
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.Findings)
	require.Greater(t, result.Summary.Backlog(), result.Summary.Exploitable())
	require.Equal(t, 0, result.Summary.FixNow)
}

func TestMain(m *testing.M) {
	if root, err := os.Getwd(); err == nil {
		for dir := root; dir != "/"; dir = filepath.Dir(dir) {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				_ = testdata.EnsureIntelDB(dir)
				break
			}
		}
	}
	os.Exit(m.Run())
}
