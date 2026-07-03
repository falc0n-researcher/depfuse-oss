package intel_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestSnapshotRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	require.NoError(t, intel.SeedDemoData(s))
	require.NoError(t, s.SetCollectedMeta())

	arts, err := s.ArtifactsForCVE("CVE-2021-44228")
	require.NoError(t, err)
	require.NotEmpty(t, arts)
	require.NoError(t, s.Close())

	dest := filepath.Join(t.TempDir(), "copy.db")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dest, data, 0o644))

	s2, err := intel.Open(dest)
	require.NoError(t, err)
	defer s2.Close()
	arts2, err := s2.ArtifactsForCVE("CVE-2021-44228")
	require.NoError(t, err)
	require.Len(t, arts2, len(arts))
}

func TestOSVCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	defer s.Close()

	matches := []models.CveMatch{{CVEID: "CVE-2021-44228", Summary: "test"}}
	require.NoError(t, s.PutOSVCache("npm", "log4js", "6.3.0", matches))

	got, ok := s.GetOSVMatches("npm", "log4js", "6.3.0")
	require.True(t, ok)
	require.Len(t, got, 1)
}

func TestArtifactsForAnyIDAliasJoin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	defer s.Close()

	now := time.Now().UTC()
	require.NoError(t, s.UpsertNormalizedRecord(intel.NormalizedRecord{
		CanonicalID: "CVE-2021-44228",
		Aliases:     []intel.AliasInput{{Alias: "CVE-2021-44228", AliasType: "CVE"}},
		Artifact: intel.ArtifactInput{
			ID: "KEV:CVE-2021-44228", Source: models.SourceKEV, TrustClass: models.TrustAuthoritative,
			Title: "KEV entry", ObservedAt: now,
		},
	}))
	require.NoError(t, s.UpsertAlias("GHSA-jfhv-c572-7mpm", "CVE-2021-44228"))

	byCVE, err := s.ArtifactsForAnyID("CVE-2021-44228")
	require.NoError(t, err)
	require.Len(t, byCVE, 1)

	byGHSA, err := s.ArtifactsForAnyID("GHSA-jfhv-c572-7mpm")
	require.NoError(t, err)
	require.Len(t, byGHSA, 1)
	require.Equal(t, byCVE[0].ID, byGHSA[0].ID)
}

func TestSchemaMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	defer s.Close()

	var version string
	err = s.DB().QueryRow(`SELECT value FROM meta WHERE key='schema_version'`).Scan(&version)
	require.NoError(t, err)
	require.Equal(t, "2", version)

	var tableCount int
	err = s.DB().QueryRow(`
SELECT COUNT(*) FROM sqlite_master
WHERE type='table' AND name IN ('vulnerabilities','vuln_aliases','artifacts','feeds','feed_runs')`).Scan(&tableCount)
	require.NoError(t, err)
	require.Equal(t, 5, tableCount)
}
