package ui_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRenderEvidenceTimeline(t *testing.T) {
	var buf bytes.Buffer
	tl := &models.EvidenceTimeline{
		CVE: "CVE-2025-29927",
		State: models.EvidenceState{
			CVE:       "CVE-2025-29927",
			Level:     models.PriorityP0,
			Hash:      "sha256:abc123",
			Signals:   models.Signals{KEV: true, Nuclei: true},
			ChangedAt: time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC),
			Events: []models.EvidenceEvent{
				{At: time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC), Source: models.SourceMetasploit, Summary: "Metasploit module indexed"},
				{At: time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC), Source: models.SourceKEV, Summary: "Listed in KEV catalog"},
			},
		},
		DecisionImpact: &models.DecisionImpact{
			PreviousLevel:  models.PriorityP4,
			ReopenRequired: true,
			Summary:        "Reopen required: level changed P4 → P0",
		},
	}
	ui.RenderEvidenceTimeline(&buf, tl)
	out := buf.String()
	require.Contains(t, out, "CVE-2025-29927")
	require.Contains(t, out, "sha256:abc123")
	require.Contains(t, out, "REOPEN")
	require.Contains(t, out, "Reopen required")
	require.Contains(t, out, "2026-07-05")
	require.Contains(t, out, "2026-07-08")
}

func TestRenderEvidenceDiff(t *testing.T) {
	var buf bytes.Buffer
	diff := &models.EvidenceDiff{
		BaselineLabel: "2026-06-01",
		CurrentLabel:  "2026-07-01",
		Changes: []models.EvidenceChange{
			{
				CVE: "CVE-2025-29927", Kind: models.EvidenceLevelChange,
				PrevLevel: models.PriorityP4, CurrLevel: models.PriorityP0,
				Summary: "Level P4 → P0",
			},
		},
	}
	ui.RenderEvidenceDiff(&buf, diff)
	out := buf.String()
	require.Contains(t, out, "CVE-2025-29927")
	require.Contains(t, out, "level_change")
	require.True(t, strings.Contains(out, "P4") && strings.Contains(out, "P0"))
}

func TestRenderPackageEvidence(t *testing.T) {
	var buf bytes.Buffer
	ui.RenderPackageEvidence(&buf, "next@15.1.0", []models.PackageEvidenceRow{
		{
			Package: "next@15.1.0", CVE: "CVE-2025-29927",
			Level: models.PriorityP0, Verdict: models.VerdictPatchNow,
			EvidenceHash: "sha256:deadbeef",
			Signals:      models.Signals{KEV: true},
		},
	})
	out := buf.String()
	require.Contains(t, out, "next@15.1.0")
	require.Contains(t, out, "CVE-2025-29927")
	require.Contains(t, out, "sha256:deadbeef")
}
