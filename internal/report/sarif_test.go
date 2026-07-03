package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/report"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRenderSARIF(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Findings: []models.Finding{{
			Component: models.Component{
				Name: "express", Version: "4.17.1", Scope: models.ScopeProd, Direct: true,
				Path: []string{"express"}, Manifest: "package.json",
			},
			CveMatch: models.CveMatch{
				CVEID: "CVE-2022-24999", Summary: "Prototype pollution in qs",
			},
			Classification: models.Classification{Priority: models.PriorityP2},
			Verdict:        models.VerdictFixSoon,
			VerdictReason:  "T2 in production dependency",
			ExposureNote:   "production dependency, direct",
		}},
	}
	require.NoError(t, report.RenderSARIF(&buf, result, "1.0.0"))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	require.Equal(t, "2.1.0", parsed["version"])
	runs := parsed["runs"].([]any)
	require.Len(t, runs, 1)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	require.Len(t, results, 1)
	res := results[0].(map[string]any)
	require.Equal(t, "CVE-2022-24999", res["ruleId"])
}
