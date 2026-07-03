package scan

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestBuildWatchDigestSummarizesEscalations(t *testing.T) {
	d := buildWatchDigest(models.WatchResult{
		Escalated: []models.FindingDelta{{CVEID: "CVE-1", Kind: models.DeltaLevelUp}},
		EPSSShifts: []models.FindingDelta{{
			CVEID: "CVE-2", Kind: models.DeltaEPSSShift, PrevEPSS: 0.12, CurrEPSS: 0.89,
		}},
	})
	require.Equal(t, 1, d.EscalatedCount)
	require.Equal(t, 1, d.EPSSShiftCount)
	require.Contains(t, d.Summary, "escalated")
	require.Contains(t, d.Summary, "EPSS shifts")
}

func TestBuildWatchDigestEmpty(t *testing.T) {
	d := buildWatchDigest(models.WatchResult{})
	require.Contains(t, d.Summary, "No reopens")
}
