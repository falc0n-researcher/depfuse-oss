package evidence_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/evidence"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func tempStore(t *testing.T) *intel.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	require.NoError(t, intel.SeedDemoData(s))
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestHashDeterministic(t *testing.T) {
	class := models.Classification{
		Priority: models.PriorityP0,
		Signals:  models.Signals{KEV: true, Nuclei: true, EPSS: 0.83},
	}
	arts := []models.RawArtifact{
		{ID: "kev-1", Source: models.SourceKEV},
		{ID: "nuc-1", Source: models.SourceNuclei},
	}
	h1 := evidence.Hash(class, arts)
	h2 := evidence.Hash(class, arts)
	require.Equal(t, h1, h2)
	require.Contains(t, h1, "sha256:")
}

func TestHashChangesWhenSignalsMove(t *testing.T) {
	arts := []models.RawArtifact{{ID: "kev-1", Source: models.SourceKEV}}
	quiet := models.Classification{Priority: models.PriorityP4, Signals: models.Signals{}}
	exploited := models.Classification{Priority: models.PriorityP0, Signals: models.Signals{KEV: true}}
	require.NotEqual(t, evidence.Hash(quiet, nil), evidence.Hash(exploited, arts))
}

func TestBuildTimelineOrdersEvents(t *testing.T) {
	s := tempStore(t)
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)
	require.NoError(t, s.UpsertArtifact(models.RawArtifact{
		ID: "kev-old", CVEID: "CVE-2025-29927", Source: models.SourceKEV,
		TrustClass: models.TrustAuthoritative, Title: "KEV", ObservedAt: early,
	}))
	require.NoError(t, s.UpsertArtifact(models.RawArtifact{
		ID: "nuc-new", CVEID: "CVE-2025-29927", Source: models.SourceNuclei,
		TrustClass: models.TrustHigh, Title: "Nuclei", ObservedAt: late,
	}))

	tl, err := evidence.BuildTimeline(s, "CVE-2025-29927", nil)
	require.NoError(t, err)
	require.Equal(t, models.PriorityP0, tl.State.Level)
	require.NotEmpty(t, tl.State.Hash)
	require.GreaterOrEqual(t, len(tl.State.Events), 2)
	require.True(t, tl.State.Events[0].At.Before(tl.State.Events[len(tl.State.Events)-1].At) ||
		tl.State.Events[0].At.Equal(tl.State.Events[len(tl.State.Events)-1].At))
}

func TestDiffStoresLevelChange(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "base.db")
	currPath := filepath.Join(t.TempDir(), "curr.db")

	base, err := intel.Open(basePath)
	require.NoError(t, err)
	require.NoError(t, intel.SeedDemoData(base))
	require.NoError(t, base.SetCollectedMeta())

	curr, err := intel.Open(currPath)
	require.NoError(t, err)
	require.NoError(t, intel.SeedDemoData(curr))
	require.NoError(t, curr.UpsertArtifact(models.RawArtifact{
		ID: "kev-CVE-2020-8209", CVEID: "CVE-2020-8209", Source: models.SourceKEV,
		TrustClass: models.TrustAuthoritative, Title: "KEV added", ObservedAt: time.Now().UTC(),
	}))
	require.NoError(t, curr.SetCollectedMeta())

	diff, err := evidence.Diff(evidence.DiffOptions{
		BaselineStore: base,
		CurrentStore:  curr,
		CVE:           "CVE-2020-8209",
	})
	require.NoError(t, err)
	require.Len(t, diff.Changes, 1)
	require.Equal(t, models.EvidenceLevelChange, diff.Changes[0].Kind)
	require.Equal(t, models.PriorityP2, diff.Changes[0].PrevLevel)
	require.Equal(t, models.PriorityP0, diff.Changes[0].CurrLevel)
}

func TestDiffSinceFiltersByObservedAt(t *testing.T) {
	s := tempStore(t)
	cutoff := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, s.UpsertArtifact(models.RawArtifact{
		ID: "kev-recent", CVEID: "CVE-2024-9999", Source: models.SourceKEV,
		TrustClass: models.TrustAuthoritative, Title: "Recent KEV", ObservedAt: cutoff.Add(24 * time.Hour),
	}))

	diff, err := evidence.Diff(evidence.DiffOptions{
		CurrentStore: s,
		Since:        cutoff,
		SinceLabel:   cutoff.Format("2006-01-02"),
	})
	require.NoError(t, err)
	require.NotEmpty(t, diff.Changes)
	found := false
	for _, ch := range diff.Changes {
		if ch.CVE == "CVE-2024-9999" {
			found = true
			require.Equal(t, models.EvidenceAdded, ch.Kind)
		}
	}
	require.True(t, found)
}
