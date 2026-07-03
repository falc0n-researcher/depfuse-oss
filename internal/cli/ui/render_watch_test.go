package ui_test

import (
	"bytes"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRenderWatchReopened(t *testing.T) {
	var buf bytes.Buffer
	ui.RenderWatch(&buf, models.WatchResult{
		Reopened: []models.WatchItem{{
			CVE: "CVE-2025-29927", Package: "next@15.1.0",
			ReopenSummary: "KEV listing added since decision",
			Reason:        "was quiet", Decision: models.DecisionAcceptedRisk,
		}},
		Silent: []models.WatchItem{{
			CVE: "CVE-2019-11358", Package: "jquery@3.4.0", Silent: true,
			Decision: models.DecisionAcceptedRisk, Reason: "dev dep",
		}},
	})
	out := buf.String()
	require.Contains(t, out, "Needs review")
	require.Contains(t, out, "CVE-2025-29927")
	require.Contains(t, out, "Silent")
}
