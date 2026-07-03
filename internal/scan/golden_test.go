package scan_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/scan"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

const goldenNextCVE = "CVE-2025-29927"

func TestGoldenScanNextApp(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "next-app")

	store, err := intel.Open(filepath.Join(t.TempDir(), "intel.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	require.NoError(t, store.UpsertArtifact(models.RawArtifact{
		ID: "nuclei-" + goldenNextCVE, CVEID: goldenNextCVE, Source: models.SourceNuclei,
		TrustClass: models.TrustHigh, Title: "Nuclei template: nextjs middleware bypass",
		URL: "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-29927.yaml", ObservedAt: now,
	}))
	require.NoError(t, store.PutOSVCache("npm", "next", "15.1.0", []models.CveMatch{{
		CVEID:         goldenNextCVE,
		Summary:       "Next.js middleware authorization bypass",
		FixedVersions: []string{"15.1.1"},
	}}))

	runner := &scan.Runner{Store: store}
	result, code, err := runner.Run(context.Background(), scan.Options{
		Path:    fixture,
		Offline: true,
		Format:  "json",
		Quiet:   true,
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	require.Equal(t, 1, result.Meta.ComponentCount)

	var nextFinding *models.Finding
	for i := range result.Findings {
		if result.Findings[i].Component.Name == "next" {
			nextFinding = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, nextFinding, "expected finding on next@15.1.0")
	require.Equal(t, goldenNextCVE, nextFinding.CveMatch.CVEID)
	require.Equal(t, models.PriorityP1, nextFinding.Classification.Priority)
	require.Equal(t, models.VerdictFixNow, nextFinding.Verdict)
	require.Equal(t, "15.1.1", nextFinding.CveMatch.FixedVersions[0])
}
