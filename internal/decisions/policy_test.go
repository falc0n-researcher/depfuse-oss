package decisions_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/decisions"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestShouldReopenQuietToWatchSilent(t *testing.T) {
	d := models.StoredDecision{
		DecidedWhenLevel:   models.PriorityP4,
		DecidedWhenSignals: models.Signals{EPSS: 0.04},
		ReopenPolicy:       models.DefaultReopenPolicy,
	}
	curr := models.Classification{
		Priority: models.PriorityP3,
		Signals:  models.Signals{EPSS: 0.06},
	}
	reopen, _ := decisions.ShouldReopen(d, curr)
	require.False(t, reopen)
}

func TestShouldReopenQuietToExploited(t *testing.T) {
	d := models.StoredDecision{
		DecidedWhenLevel: models.PriorityP4,
		ReopenPolicy:     models.DefaultReopenPolicy,
	}
	curr := models.Classification{Priority: models.PriorityP0, Signals: models.Signals{KEV: true}}
	reopen, summary := decisions.ShouldReopen(d, curr)
	require.True(t, reopen)
	require.Contains(t, summary, "P0")
}

func TestShouldReopenKEVAdded(t *testing.T) {
	d := models.StoredDecision{
		DecidedWhenLevel:   models.PriorityP2,
		DecidedWhenSignals: models.Signals{},
		ReopenPolicy:       []models.ReopenTrigger{models.ReopenKEVAdded},
	}
	curr := models.Classification{Priority: models.PriorityP0, Signals: models.Signals{KEV: true}}
	reopen, summary := decisions.ShouldReopen(d, curr)
	require.True(t, reopen)
	require.Contains(t, summary, "KEV")
}

func TestShouldReopenEPSSThreshold(t *testing.T) {
	d := models.StoredDecision{
		DecidedWhenLevel:   models.PriorityP3,
		DecidedWhenSignals: models.Signals{EPSS: 0.12},
		ReopenPolicy:       []models.ReopenTrigger{models.ReopenEPSSThreshold},
	}
	curr := models.Classification{
		Priority: models.PriorityP3,
		Signals:  models.Signals{EPSS: 0.91},
	}
	reopen, summary := decisions.ShouldReopen(d, curr)
	require.True(t, reopen)
	require.Contains(t, summary, "0.91")
}

func TestShouldReopenEPSSMinorDeltaSilent(t *testing.T) {
	d := models.StoredDecision{
		DecidedWhenLevel:   models.PriorityP3,
		DecidedWhenSignals: models.Signals{EPSS: 0.12},
		ReopenPolicy:       []models.ReopenTrigger{models.ReopenEPSSThreshold},
	}
	curr := models.Classification{
		Priority: models.PriorityP3,
		Signals:  models.Signals{EPSS: 0.20},
	}
	reopen, _ := decisions.ShouldReopen(d, curr)
	require.False(t, reopen)
}

func TestMatchSpecificity(t *testing.T) {
	f := decisions.File{Decisions: []models.StoredDecision{
		{CVE: "CVE-2025-29927", Decision: models.DecisionAcceptedRisk},
		{CVE: "CVE-2025-29927", Package: "next", Version: "15.1.0", Decision: models.DecisionBlocked, Reason: "specific"},
	}}
	got, ok := f.Match(models.Finding{
		Component: models.Component{Name: "next", Version: "15.1.0"},
		CveMatch:  models.CveMatch{CVEID: "CVE-2025-29927"},
	})
	require.True(t, ok)
	require.Equal(t, models.DecisionBlocked, got.Decision)
}
