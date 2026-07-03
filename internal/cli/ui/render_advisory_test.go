package ui_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRenderScanCVELookupSingleTable(t *testing.T) {
	var buf bytes.Buffer
	ui.RenderScan(&buf, models.ScanResult{
		Meta: models.ScanMeta{
			ComponentCount: 1,
			FindingCount:   1,
			InputMode:      models.InputModeCVE,
			InputPath:      "CVE-2026-50137",
		},
		Summary: models.ScanSummary{Total: 1, P3: 1, OK: 1},
		Findings: []models.Finding{{
			Component: models.Component{Name: "@budibase/server", Version: "< 3.39.0", Scope: models.ScopeDev, Direct: true},
			CveMatch: models.CveMatch{
				CVEID:         "CVE-2026-50137",
				GHSAID:        "GHSA-35c4-rvc8-frhm",
				OSVID:         "GHSA-35c4-rvc8-frhm",
				Summary:       "Budibase: POST /api/attachments/:datasourceId/url is unauthenticated",
				FixedVersions: []string{"3.39.0"},
				References: []string{
					"https://github.com/Budibase/budibase/security/advisories/GHSA-35c4-rvc8-frhm",
				},
			},
			Classification: models.Classification{Priority: models.PriorityP3},
			Verdict:        models.VerdictOK,
			ExposureNote:   "Advisory-only lookup (not tied to an installed dependency version)",
		}},
	})

	out := buf.String()
	require.Contains(t, out, "CVE lookup")
	require.Contains(t, out, "Summary")
	require.Contains(t, out, "GHSA-35c4-rvc8-frhm")
	// The lookup table no longer carries a full-URL Link column (it overflowed
	// the terminal); reference links live behind --verbose / the evidence table.
	require.NotContains(t, out, "│ Link ")
	require.Contains(t, out, "use --verbose for full advisory details and reference links")
	require.NotContains(t, out, "Development")
	require.NotContains(t, out, "Advisories")
}

func TestRenderScanAdvisoryIndexCompact(t *testing.T) {
	var buf bytes.Buffer
	ui.RenderScan(&buf, models.ScanResult{
		Meta: models.ScanMeta{ComponentCount: 1, FindingCount: 1},
		Summary: models.ScanSummary{
			Total: 1, P4: 1, OK: 1,
		},
		Findings: []models.Finding{{
			Component: models.Component{Name: "@budibase/server", Version: "3.38.0", Scope: models.ScopeProd, Direct: true},
			CveMatch: models.CveMatch{
				CVEID:         "CVE-2026-50137",
				GHSAID:        "GHSA-35c4-rvc8-frhm",
				OSVID:         "GHSA-35c4-rvc8-frhm",
				Summary:       "Budibase: POST /api/attachments/:datasourceId/url is unauthenticated",
				FixedVersions: []string{"3.39.0"},
				References: []string{
					"https://github.com/Budibase/budibase/security/advisories/GHSA-35c4-rvc8-frhm",
				},
			},
			Classification: models.Classification{Priority: models.PriorityP4},
			Verdict:        models.VerdictOK,
		}},
	})

	out := buf.String()
	require.Contains(t, out, "Advisories")
	require.Contains(t, out, "GHSA-35c4-rvc8-frhm")
	require.NotContains(t, out, "Advisory sources")
}

func TestRenderScanFindingsTableAdvisoryLink(t *testing.T) {
	var buf bytes.Buffer
	ui.RenderScan(&buf, models.ScanResult{
		Meta:    models.ScanMeta{ComponentCount: 1, FindingCount: 1},
		Summary: models.ScanSummary{Total: 1, P4: 1, OK: 1},
		Findings: []models.Finding{{
			Component: models.Component{Name: "@budibase/server", Version: "3.38.0", Scope: models.ScopeProd, Direct: true},
			CveMatch: models.CveMatch{
				CVEID:  "CVE-2026-50137",
				GHSAID: "GHSA-35c4-rvc8-frhm",
				OSVID:  "GHSA-35c4-rvc8-frhm",
				References: []string{
					"https://github.com/Budibase/budibase/security/advisories/GHSA-35c4-rvc8-frhm",
				},
			},
			Classification: models.Classification{Priority: models.PriorityP4},
			Verdict:        models.VerdictOK,
		}},
	})

	out := buf.String()
	require.Contains(t, out, "Link")
	require.Contains(t, out, "github.com/Budibase/budibase/security/advisories/GHSA-35c4-rvc8-frhm")
}

func TestRenderScanHidesRedundantAdvisoriesForManyFindings(t *testing.T) {
	findings := make([]models.Finding, 13)
	for i := range findings {
		ghsa := fmt.Sprintf("GHSA-%04d-bbbb-cccc", i)
		findings[i] = models.Finding{
			Component: models.Component{Name: "@budibase/server", Version: "3.38.0", Scope: models.ScopeProd, Direct: true},
			CveMatch: models.CveMatch{
				CVEID:   fmt.Sprintf("CVE-2026-%05d", i),
				GHSAID:  ghsa,
				OSVID:   ghsa,
				Summary: "example advisory",
				Details: "long details that should not appear by default",
			},
			Classification: models.Classification{Priority: models.PriorityP4},
			Verdict:        models.VerdictOK,
		}
	}

	var buf bytes.Buffer
	ui.RenderScan(&buf, models.ScanResult{
		Meta:     models.ScanMeta{ComponentCount: 1, FindingCount: 13},
		Summary:  models.ScanSummary{Total: 13, P4: 13, OK: 13},
		Findings: findings,
	})

	out := buf.String()
	require.NotContains(t, out, "Advisories")
	require.NotContains(t, out, "long details that should not appear")
	require.Contains(t, out, "Production · direct")
}

func TestRenderScanAdvisoryVerboseDetails(t *testing.T) {
	var buf bytes.Buffer
	ui.RenderScan(&buf, models.ScanResult{
		Verbose: true,
		Meta: models.ScanMeta{
			ComponentCount: 1,
			FindingCount:   1,
			InputMode:      models.InputModeCVE,
		},
		Summary: models.ScanSummary{Total: 1, P4: 1, OK: 1},
		Findings: []models.Finding{{
			Component: models.Component{Name: "@theia/debug", Version: "< 1.69.0", Scope: models.ScopeDev},
			CveMatch: models.CveMatch{
				CVEID:     "CVE-2026-44691",
				OSVID:     "GHSA-g9jw-92q7-g7fj",
				GHSAID:    "GHSA-g9jw-92q7-g7fj",
				Summary:   "Arbitrary Command Execution via Untrusted Workspace Task Definitions",
				Details:   "In Eclipse Theia versions prior to 1.69.0, custom task definitions could be executed without workspace trust.",
				Severity:  "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				Published: time.Date(2026, 6, 18, 0, 0, 0, 0, time.UTC),
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2026-44691",
					"https://github.com/eclipse-theia/theia/issues/16889",
				},
			},
			Classification: models.Classification{Priority: models.PriorityP4},
			Verdict:        models.VerdictOK,
		}},
	})

	out := buf.String()
	require.Contains(t, out, "CVE lookup")
	require.Contains(t, out, "Details")
	require.Contains(t, out, "nvd.nist.gov/vuln/detail/CVE-2026-44691")
	require.Contains(t, out, "GitHub Issue")
	require.Contains(t, out, "custom task definitions could be executed")
	require.NotContains(t, out, "Advisories")
}
