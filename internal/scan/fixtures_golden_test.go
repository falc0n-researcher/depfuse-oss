package scan_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/scan"
	"github.com/falc0n-researcher/depfuse-oss/internal/testdata"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func openSeededStore(t *testing.T, roots ...string) (*intel.Store, string) {
	t.Helper()
	root := repoRoot(t)
	if len(roots) == 0 {
		roots = []string{filepath.Join(root, testdata.DemoFixtureRoot)}
	} else {
		for i, r := range roots {
			if !filepath.IsAbs(r) {
				roots[i] = filepath.Join(root, r)
			}
		}
	}
	dbPath := filepath.Join(t.TempDir(), "intel.db")
	require.NoError(t, testdata.SeedIntelDB(dbPath, roots...))
	store, err := intel.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store, dbPath
}

func TestGoldenScanExpressApp(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "express-app")
	store, dbPath := openSeededStore(t, fixture)

	runner := &scan.Runner{Store: store}
	result, code, err := runner.Run(context.Background(), scan.Options{
		Path:    fixture,
		Offline: true,
		DBPath:  dbPath,
		Quiet:   true,
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)

	require.NotNil(t, result.Meta.Coverage)
	require.Equal(t, "complete", result.Meta.Coverage.Status)
	require.True(t, result.Meta.Coverage.HasLockfile)
	require.GreaterOrEqual(t, result.Meta.ComponentCount, 4)
	require.GreaterOrEqual(t, result.Summary.Total, 8)
	require.Equal(t, 0, result.Summary.FixNow)
	require.Equal(t, 0, result.Summary.WeaponizedExposure())
	require.Equal(t, result.Summary.Total, result.Summary.OK)

	var qsTransitive *models.Finding
	for i := range result.Findings {
		f := &result.Findings[i]
		require.Equal(t, models.PriorityP4, f.Classification.Priority)
		require.Equal(t, models.VerdictOK, f.Verdict)
		if f.Component.Name == "qs" && len(f.Component.Path) > 0 && f.Component.Path[0] == "express" {
			qsTransitive = f
		}
	}
	require.NotNil(t, qsTransitive, "expected transitive qs finding under express")
}

func TestGoldenScanNoiseApp(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "noise-app")
	store, dbPath := openSeededStore(t, fixture)

	runner := &scan.Runner{Store: store}
	result, code, err := runner.Run(context.Background(), scan.Options{
		Path:    fixture,
		Offline: true,
		DBPath:  dbPath,
		Quiet:   true,
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	require.Equal(t, 0, result.Meta.FindingCount)
	require.Equal(t, 0, result.Summary.Total)
	require.NotNil(t, result.Meta.Coverage)
	require.Equal(t, "complete", result.Meta.Coverage.Status)

	_, ciCode, err := runner.Run(context.Background(), scan.Options{
		Path:     fixture,
		Offline:  true,
		DBPath:   dbPath,
		Quiet:    true,
		CI:       true,
		FailOn:   "T0,T1",
		SkipEmit: true,
	})
	require.NoError(t, err)
	require.Equal(t, 0, ciCode)
}
