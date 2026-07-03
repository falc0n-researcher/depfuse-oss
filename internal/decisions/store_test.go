package decisions_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/decisions"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	root := t.TempDir()
	path, err := decisions.DefaultPath(root)
	require.NoError(t, err)

	d := models.StoredDecision{
		CVE: "CVE-2025-29927", Package: "next", Version: "15.1.0",
		Decision: models.DecisionAcceptedRisk, Reason: "not deployed",
		DecidedAt: time.Now().UTC(), DecidedWhenLevel: models.PriorityP4,
		DecidedWhenEvidenceHash: "sha256:abc", ReopenPolicy: models.DefaultReopenPolicy,
	}
	file := decisions.File{Path: path, Decisions: []models.StoredDecision{d}}
	require.NoError(t, decisions.Save(file))

	loaded, err := decisions.Load(root)
	require.NoError(t, err)
	require.Len(t, loaded.Decisions, 1)
	require.Equal(t, models.PriorityP4, loaded.Decisions[0].DecidedWhenLevel)
	require.Equal(t, "P4", loaded.Decisions[0].DecidedWhenLevel.String())
}

func TestApplyAcceptedSilent(t *testing.T) {
	file := decisions.File{Decisions: []models.StoredDecision{{
		CVE: "CVE-2025-29927", Package: "next", Version: "15.1.0",
		Decision: models.DecisionAcceptedRisk, Reason: "dev only",
		DecidedWhenLevel: models.PriorityP4, DecidedWhenSignals: models.Signals{},
	}}}
	f := models.Finding{
		Component:      models.Component{Name: "next", Version: "15.1.0"},
		CveMatch:       models.CveMatch{CVEID: "CVE-2025-29927"},
		Classification: models.Classification{Priority: models.PriorityP4, Signals: models.Signals{EPSS: 0.04}},
	}
	active, accepted, _ := decisions.Apply(nil, []models.Finding{f}, file)
	require.Empty(t, active)
	require.Len(t, accepted, 1)
	require.True(t, accepted[0].AcceptedRisk)
}

func TestApplyReopenOnKEV(t *testing.T) {
	file := decisions.File{Decisions: []models.StoredDecision{{
		CVE: "CVE-2025-29927", Decision: models.DecisionAcceptedRisk, Reason: "was quiet",
		DecidedWhenLevel: models.PriorityP4, DecidedWhenSignals: models.Signals{},
		ReopenPolicy: models.DefaultReopenPolicy,
	}}}
	f := models.Finding{
		Component: models.Component{Name: "next", Version: "15.1.0"},
		CveMatch:  models.CveMatch{CVEID: "CVE-2025-29927"},
		Classification: models.Classification{
			Priority: models.PriorityP0, Signals: models.Signals{KEV: true},
		},
	}
	active, accepted, _ := decisions.Apply(nil, []models.Finding{f}, file)
	require.Len(t, active, 1)
	require.True(t, active[0].Reopened)
	require.Empty(t, accepted)
}

func TestLoadMissingFileEmpty(t *testing.T) {
	root := t.TempDir()
	file, err := decisions.Load(root)
	require.NoError(t, err)
	require.Empty(t, file.Decisions)
	_, err = os.Stat(filepath.Join(root, ".depfuse", "decisions.yaml"))
	require.Error(t, err)
}
