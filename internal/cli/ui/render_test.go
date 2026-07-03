package ui_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRenderScanActionEvidenceTable(t *testing.T) {
	var buf bytes.Buffer
	ui.RenderScan(&buf, models.ScanResult{
		Meta:    models.ScanMeta{ComponentCount: 1, FindingCount: 1},
		Verbose: true,
		Summary: models.ScanSummary{
			Total: 1, P1: 1, FixSoon: 1,
		},
		Findings: []models.Finding{{
			Component: models.Component{Name: "advisory-lookup", Version: "n/a", Scope: models.ScopeDev},
			CveMatch:  models.CveMatch{CVEID: "CVE-2025-29927", GHSAID: "GHSA-f82v-jwr5-mffw"},
			Classification: models.Classification{
				Priority: models.PriorityP1,
				Evidence: []models.Citation{
					{Claim: "Exploit-DB entry indexed for this CVE", Source: models.SourceExploitDB, URL: "https://www.exploit-db.com/exploits/52124"},
					{Claim: "Nuclei scanner template exists for this CVE", Source: models.SourceNuclei, URL: "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-29927.yaml"},
				},
				Signals: models.Signals{Nuclei: true, ExploitDB: true},
			},
			Verdict: models.VerdictFixSoon,
		}},
	})

	out := buf.String()
	require.Contains(t, out, "Action required")
	require.Contains(t, out, "CVE-2025-29927")
	require.Contains(t, out, "Evidence")
	require.Contains(t, out, "exploit-db.com/exploits/52124")
	require.Contains(t, out, "http/cves/2025/CVE-2025-29927.yaml")
}

func TestRenderScanDefaultSkipsEvidenceTable(t *testing.T) {
	var buf bytes.Buffer
	ui.RenderScan(&buf, models.ScanResult{
		Meta:    models.ScanMeta{ComponentCount: 1, FindingCount: 1},
		Summary: models.ScanSummary{Total: 1, P1: 1, FixSoon: 1},
		Findings: []models.Finding{{
			Component:      models.Component{Name: "pkg", Version: "1.0.0", Scope: models.ScopeProd, Direct: true},
			CveMatch:       models.CveMatch{CVEID: "CVE-2025-29927"},
			Classification: models.Classification{Priority: models.PriorityP1, Signals: models.Signals{Nuclei: true}},
			Verdict:        models.VerdictFixSoon,
		}},
	})
	out := buf.String()
	require.Contains(t, out, "Action required")
	require.NotContains(t, out, "│ Source │")
}

func TestRenderScanActionEvidenceTableHeaders(t *testing.T) {
	var buf bytes.Buffer
	ui.RenderScan(&buf, models.ScanResult{
		Meta:    models.ScanMeta{FindingCount: 1},
		Verbose: true,
		Summary: models.ScanSummary{Total: 1, P0: 1, FixNow: 1},
		Findings: []models.Finding{{
			Component: models.Component{Name: "next", Version: "15.1.0", Scope: models.ScopeProd, Direct: true},
			CveMatch:  models.CveMatch{CVEID: "CVE-2025-29927"},
			Classification: models.Classification{
				Priority: models.PriorityP0,
				Evidence: []models.Citation{
					{Claim: "Listed in VulnCheck Known Exploited Vulnerabilities catalog", Source: models.SourceKEV, URL: "https://vulncheck.com/kev"},
				},
				Signals: models.Signals{KEV: true},
			},
			Verdict: models.VerdictFixNow,
		}},
	})

	lines := strings.Split(buf.String(), "\n")
	var sawEvidenceHeader bool
	for _, line := range lines {
		if strings.Contains(line, "Evidence") && strings.Contains(line, "URL") && strings.Contains(line, "CVE") {
			sawEvidenceHeader = true
			break
		}
	}
	require.True(t, sawEvidenceHeader)
}
