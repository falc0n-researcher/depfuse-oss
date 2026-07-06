package report_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/report"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRenderMarkdownHTML(t *testing.T) {
	result := models.ScanResult{
		Meta:    models.ScanMeta{Timestamp: time.Now().UTC(), SnapshotVersion: "test"},
		Summary: models.ScanSummary{P0: 1, P1: 1, P3: 1, P4: 1, FixNow: 1},
		Findings: []models.Finding{{
			Component:      models.Component{Name: "express", Version: "4.17.1", Scope: models.ScopeProd, Direct: true},
			CveMatch:       models.CveMatch{CVEID: "CVE-2022-22965"},
			Classification: models.Classification{Priority: models.PriorityP1},
			Verdict:        models.VerdictFixNow,
			ExposureNote:   "production dependency, direct",
			Briefing:       "Test briefing",
		}},
	}
	dir := t.TempDir()
	require.NoError(t, report.WriteOutputs(dir, []string{"md", "html"}, result))
	require.FileExists(t, filepath.Join(dir, "report.md"))
	require.FileExists(t, filepath.Join(dir, "report.html"))
	content, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	require.Contains(t, string(content), "Security Dashboard")
	require.Contains(t, string(content), "class=\"dash\"")
	require.Contains(t, string(content), "findings-table")
}

func TestRankAndSummarize(t *testing.T) {
	findings := []models.Finding{
		{Component: models.Component{Scope: models.ScopeDev}, Classification: models.Classification{Priority: models.PriorityP1, Confidence: 0.5}, CveMatch: models.CveMatch{CVEID: "B"}},
		{Component: models.Component{Scope: models.ScopeProd, Direct: true}, Classification: models.Classification{Priority: models.PriorityP1, Confidence: 0.9}, CveMatch: models.CveMatch{CVEID: "A"}},
	}
	report.Rank(findings)
	require.Equal(t, "A", findings[0].CveMatch.CVEID)
	s := report.Summarize(findings)
	require.Equal(t, 2, s.WeaponizedExposure())
}

func TestSummarizeBacklogExcludesT2(t *testing.T) {
	findings := []models.Finding{
		{Classification: models.Classification{Priority: models.PriorityP2}, Verdict: models.VerdictFixSoon},
		{Classification: models.Classification{Priority: models.PriorityP3}, Verdict: models.VerdictOK},
		{Classification: models.Classification{Priority: models.PriorityP4}, Verdict: models.VerdictOK},
	}
	s := report.Summarize(findings)
	require.Equal(t, 0, s.WeaponizedExposure())
	require.Equal(t, 1, s.FixSoon)
	require.Equal(t, 2, s.Backlog())
}
