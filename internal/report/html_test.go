package report_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/report"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRenderHTMLProfessional(t *testing.T) {
	result := models.ScanResult{
		Meta: models.ScanMeta{
			Timestamp:       time.Now().UTC(),
			SnapshotVersion: "test",
			SnapshotHash:    "abc123",
			InputPath:       "demo_package",
			ComponentCount:  10,
			FindingCount:    2,
			DurationMS:      500,
		},
		Summary: models.ScanSummary{Total: 2, P0: 1, P1: 1, FixNow: 2},
		Findings: []models.Finding{{
			Component: models.Component{Name: "jquery", Version: "3.2.1", Scope: models.ScopeProd, Direct: true},
			CveMatch:  models.CveMatch{CVEID: "CVE-2020-11023", GHSAID: "GHSA-test"},
			Classification: models.Classification{
				Priority: models.PriorityP0,
				Signals:  models.Signals{KEV: true, EPSS: 0.84},
				Evidence: []models.Citation{{
					Source: models.SourceKEV,
					Claim:  "Listed in VulnCheck KEV",
					URL:    "https://vulncheck.com/kev/CVE-2020-11023",
				}},
			},
			Verdict: models.VerdictFixNow,
			Remediation: &models.Remediation{
				FixAvailable: true,
				Installed:    "3.2.1",
				FixVersion:   "3.5.0",
				Jump:         models.JumpMinor,
			},
			Receipts: []models.VerdictReceipt{{Kind: models.ReceiptKEV, Claim: "Listed in VulnCheck KEV", URL: "https://vulncheck.com/kev/CVE-2020-11023"}},
		}},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	require.NoError(t, report.RenderHTML(path, result))
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	html := string(content)
	require.Contains(t, html, "Geist Mono")
	require.Contains(t, html, "Weaponized CVE intelligence for npm dependencies")
	require.Contains(t, html, "Dependency exposure · exploit-evidence assessment")
	require.Contains(t, html, "class=\"dash\"")
	require.Contains(t, html, "dash-header")
	require.Contains(t, html, "findings-table")
	require.Contains(t, html, "Priority Actions")
	require.Contains(t, html, "badge-kev")
	require.Contains(t, html, `class="badge badge-kev badge-link" href="https://vulncheck.com/kev/CVE-2020-11023"`)
	require.Contains(t, html, "Verdict Receipts")
	require.Contains(t, html, "CVE-2020-11023")
	require.Contains(t, html, "priority-p0")
	require.Contains(t, html, "Minor release")
	require.NotContains(t, html, "report-nav")
	require.NotContains(t, html, "report-page")
	require.NotContains(t, html, "(patch)")
	require.NotContains(t, html, "tier-p0")
}

func TestRenderHTMLWriter(t *testing.T) {
	result := models.ScanResult{
		Meta:    models.ScanMeta{Timestamp: time.Now().UTC()},
		Summary: models.ScanSummary{Total: 0},
	}
	var b strings.Builder
	require.NoError(t, report.RenderHTMLWriter(&b, result))
	require.Contains(t, b.String(), "<!DOCTYPE html>")
}

func TestRenderHTMLPackageContextInRollupAndAccordion(t *testing.T) {
	ctx := models.PackageContext{
		Name:            "express",
		Description:     "Fast, unopinionated, minimalist web framework for Node.js.",
		WeeklyDownloads: 109_100_000,
		License:         "MIT",
		Homepage:        "https://expressjs.com",
		Popularity:      models.PopularityUbiquitous,
	}
	result := models.ScanResult{
		Meta: models.ScanMeta{
			Timestamp:       time.Now().UTC(),
			InputPath:       "express@4.17.1",
			ResolvedPackage: "express@4.17.1",
			PackageContext:  &ctx,
			ComponentCount:  2,
			FindingCount:    2,
		},
		Summary: models.ScanSummary{Total: 2, P3: 2, OK: 2},
		Components: []models.Component{
			{Name: "express", Version: "4.17.1", Direct: true, Path: []string{"express"}},
			{Name: "qs", Version: "6.7.0", Direct: false, Path: []string{"express", "qs"}},
		},
		Findings: []models.Finding{
			{
				Component:      models.Component{Name: "express", Version: "4.17.1", Direct: true, Path: []string{"express"}},
				CveMatch:       models.CveMatch{CVEID: "CVE-2024-29041"},
				Classification: models.Classification{Priority: models.PriorityP4},
				Verdict:        models.VerdictOK,
			},
			{
				Component:      models.Component{Name: "qs", Version: "6.7.0", Direct: false, Path: []string{"express", "qs"}},
				CveMatch:       models.CveMatch{CVEID: "CVE-2022-24999"},
				Classification: models.Classification{Priority: models.PriorityP3},
				Verdict:        models.VerdictOK,
				PackageContext: &models.PackageContext{
					Name:            "qs",
					Description:     "A querystring parser that supports nesting and arrays.",
					WeeklyDownloads: 76_000_000,
					License:         "BSD-3-Clause",
					Popularity:      models.PopularityUbiquitous,
				},
			},
		},
		Packages: map[string]models.PackageContext{
			"express": ctx,
			"qs": {
				Name:            "qs",
				Description:     "A querystring parser that supports nesting and arrays.",
				WeeklyDownloads: 76_000_000,
				License:         "BSD-3-Clause",
				Popularity:      models.PopularityUbiquitous,
			},
		},
	}
	var b strings.Builder
	require.NoError(t, report.RenderHTMLWriter(&b, result))
	html := b.String()
	require.Contains(t, html, "Priority Upgrades")
	require.Contains(t, html, "Fast, unopinionated, minimalist web framework")
	require.Contains(t, html, "querystring parser")
	require.Contains(t, html, "expressjs.com")
	require.Contains(t, html, "pkg-profile")
	require.Contains(t, html, "stat-pill")
}
