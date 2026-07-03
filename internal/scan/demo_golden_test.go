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

const (
	demoNextCVE   = "CVE-2025-29927"
	demoJQueryCVE = "CVE-2019-11358"
)

func TestGoldenScanDemoPackage(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, testdata.DemoFixtureRoot)
	dbPath := filepath.Join(t.TempDir(), "intel.db")

	require.NoError(t, testdata.SeedIntelDB(dbPath, filepath.Join(root, testdata.DemoFixtureRoot)))

	runner := &scan.Runner{}
	store, err := intel.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	runner.Store = store

	result, code, err := runner.Run(context.Background(), scan.Options{
		Path:    fixture,
		Offline: true,
		DBPath:  dbPath,
		Format:  "json",
		Quiet:   true,
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	require.Greater(t, result.Meta.ComponentCount, 3)
	require.Greater(t, result.Summary.Total, 5)

	var nextHold, jqueryFix *models.Finding
	for i := range result.Findings {
		f := &result.Findings[i]
		switch {
		case f.Component.Name == "next" && f.CveMatch.CVEID == demoNextCVE:
			nextHold = f
		case f.Component.Name == "jquery" && f.CveMatch.CVEID == demoJQueryCVE:
			jqueryFix = f
		}
	}

	require.NotNil(t, nextHold, "expected Exploited FIX NOW on next@%s", demoNextCVE)
	require.Equal(t, models.PriorityP0, nextHold.Classification.Priority)
	require.True(t, nextHold.Classification.Signals.KEV)
	require.Equal(t, models.VerdictFixNow, nextHold.Verdict)

	require.NotNil(t, jqueryFix, "expected T2 FIX on jquery@%s", demoJQueryCVE)
	require.Equal(t, models.PriorityP2, jqueryFix.Classification.Priority)
	require.True(t, jqueryFix.Classification.Signals.ExploitDB)
	require.Equal(t, models.VerdictFixSoon, jqueryFix.Verdict)

	require.Equal(t, 1, result.Summary.FixNow)
	require.GreaterOrEqual(t, result.Summary.FixSoon, 1)
	require.Greater(t, result.Summary.Backlog(), result.Summary.Exploitable())
	require.Greater(t, result.Summary.Backlog(), 0)
}

func TestGoldenScanDemoPackageCIFailsOnT0(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, testdata.DemoFixtureRoot)
	dbPath := filepath.Join(t.TempDir(), "intel.db")
	require.NoError(t, testdata.SeedIntelDB(dbPath, filepath.Join(root, testdata.DemoFixtureRoot)))

	store, err := intel.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	runner := &scan.Runner{Store: store}
	_, code, err := runner.Run(context.Background(), scan.Options{
		Path:    fixture,
		Offline: true,
		DBPath:  dbPath,
		Format:  "json",
		Quiet:   true,
		CI:      true,
		FailOn:  "T0,T1",
	})
	require.NoError(t, err)
	require.Equal(t, 1, code)
}
