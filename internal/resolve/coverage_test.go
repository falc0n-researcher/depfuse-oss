package resolve_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestComputeCoverageCompleteWithLockfile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o644))
	cov := resolve.ComputeCoverage(root, []models.Component{
		{Name: "express", Version: "4.17.1", Direct: true},
		{Name: "qs", Version: "6.7.0", Path: []string{"express"}},
	}, resolve.TreeStats{Total: 2, Direct: 1, Transitive: 1}, 0, resolve.SnapshotModeOnline)
	require.NotNil(t, cov)
	require.Equal(t, resolve.CoverageComplete, cov.Status)
	require.True(t, cov.HasLockfile)
}

func TestComputeCoveragePeerDependenciesAndEmbeddedSnapshot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o644))
	cov := resolve.ComputeCoverage(root, []models.Component{
		{Name: "express", Version: "4.17.1", Direct: true},
		{Name: "qs", Version: "6.7.0", Path: []string{"express"}},
	}, resolve.TreeStats{Total: 2, Direct: 1, Transitive: 1}, 3, resolve.SnapshotModeEmbeddedSnapshot)
	require.NotNil(t, cov)
	require.Equal(t, resolve.CoveragePartial, cov.Status)
	require.Equal(t, 3, cov.PeerDependencyCount)
	require.Equal(t, resolve.SnapshotModeEmbeddedSnapshot, cov.SnapshotMode)
	require.Contains(t, cov.Message, "embedded weaponized-only index")
}

func TestComputeCoverageIncompleteWithoutLockfile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"lodash":"^4.17.0"}}`), 0o644))
	cov := resolve.ComputeCoverage(root, []models.Component{
		{Name: "lodash", Version: "4.17.20", Direct: true, Spec: "^4.17.0"},
	}, resolve.TreeStats{Total: 1, Direct: 1}, 0, resolve.SnapshotModeOnline)
	require.Equal(t, resolve.CoverageIncomplete, cov.Status)
	require.Contains(t, cov.Message, "SCAN INCOMPLETE")
}

func TestComputeCoverageIncompleteWithUnresolved(t *testing.T) {
	root := t.TempDir()
	cov := resolve.ComputeCoverage(root, []models.Component{
		{Name: "next", Version: "*", Direct: true, Unresolved: true, Spec: "^13.0.0"},
	}, resolve.TreeStats{Total: 1, Direct: 1}, 0, resolve.SnapshotModeOnline)
	require.Equal(t, resolve.CoverageIncomplete, cov.Status)
	require.Equal(t, 1, cov.UnresolvedCount)
}
