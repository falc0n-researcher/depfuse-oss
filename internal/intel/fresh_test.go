package intel_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestNeedsRefreshMissing(t *testing.T) {
	needs, err := intel.NeedsRefresh(filepath.Join(t.TempDir(), "missing.db"), time.Hour)
	require.NoError(t, err)
	require.True(t, needs)
}

func TestNeedsRefreshFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.db")
	store, err := intel.Open(path)
	require.NoError(t, err)
	require.NoError(t, intel.SeedDemoData(store))
	require.NoError(t, store.SetCollectedMeta())
	require.NoError(t, store.Close())

	needs, err := intel.NeedsRefresh(path, 4*time.Hour)
	require.NoError(t, err)
	require.False(t, needs)
}

func TestNeedsRefreshStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.db")
	store, err := intel.Open(path)
	require.NoError(t, err)
	require.NoError(t, intel.SeedDemoData(store))
	require.NoError(t, store.SetCollectedMeta())
	require.NoError(t, store.Close())

	needs, err := intel.NeedsRefresh(path, time.Nanosecond)
	require.NoError(t, err)
	require.True(t, needs)
}
