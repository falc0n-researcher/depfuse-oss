package scan_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/decisions"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/scan"
	"github.com/falc0n-researcher/depfuse-oss/internal/testdata"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRunDecisionsExplainReopensOnLevelIncrease(t *testing.T) {
	root := repoRoot(t)
	dbPath := filepath.Join(t.TempDir(), "intel.db")
	require.NoError(t, testdata.SeedIntelDB(dbPath, filepath.Join(root, testdata.DemoFixtureRoot)))

	projectDir := t.TempDir()
	file := decisions.File{Path: filepath.Join(projectDir, ".depfuse", "decisions.yaml")}
	file.Add(models.StoredDecision{
		CVE: demoJQueryCVE, Package: "jquery", Version: "3.2.1",
		Decision: models.DecisionAcceptedRisk, Reason: "not deployed",
		DecidedAt: time.Now().UTC(), DecidedWhenLevel: models.PriorityP4,
		ReopenPolicy: models.DefaultReopenPolicy,
	})
	require.NoError(t, decisions.Save(file))

	store, err := intel.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	runner := &scan.Runner{Store: store}
	explains, err := runner.RunDecisionsExplain(context.Background(), demoJQueryCVE, projectDir, dbPath, true)
	require.NoError(t, err)
	require.Len(t, explains, 1)
	require.Equal(t, models.PriorityP4, explains[0].Decision.DecidedWhenLevel)
	require.Equal(t, models.PriorityP2, explains[0].CurrentLevel)
	require.True(t, explains[0].WouldReopen)
	require.Contains(t, explains[0].ReopenReason, "P2")
}

func TestRunDecisionsExplainNoStoredDecision(t *testing.T) {
	root := repoRoot(t)
	dbPath := filepath.Join(t.TempDir(), "intel.db")
	require.NoError(t, testdata.SeedIntelDB(dbPath, filepath.Join(root, testdata.DemoFixtureRoot)))

	store, err := intel.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	runner := &scan.Runner{Store: store}
	_, err = runner.RunDecisionsExplain(context.Background(), demoJQueryCVE, t.TempDir(), dbPath, true)
	require.Error(t, err)
}
