package scan

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestBuildCVEFindingsUsesAffectedPackages(t *testing.T) {
	cm := models.CveMatch{
		CVEID:  "CVE-2026-44691",
		GHSAID: "GHSA-g9jw-92q7-g7fj",
		AffectedPackages: []models.AffectedPackage{
			{Name: "@theia/debug", Ecosystem: "npm", FixedVersion: "1.69.0"},
			{Name: "@theia/task", Ecosystem: "npm", FixedVersion: "1.69.0"},
			{Name: "@theia/workspace", Ecosystem: "npm", FixedVersion: "1.69.0"},
		},
	}
	class := models.Classification{Priority: models.PriorityP4}
	findings := buildCVEFindings(cm, class, Options{})

	require.Len(t, findings, 3)
	require.Equal(t, "@theia/debug", findings[0].Component.Name)
	require.Equal(t, "< 1.69.0", findings[0].Component.Version)
	require.Equal(t, "1.69.0", findings[0].CveMatch.FixedVersions[0])
}

func TestBuildCVEFindingsFallbackWithoutPackages(t *testing.T) {
	cm := models.CveMatch{CVEID: "CVE-2026-00000"}
	class := models.Classification{Priority: models.PriorityP4}
	findings := buildCVEFindings(cm, class, Options{})

	require.Len(t, findings, 1)
	require.Equal(t, "advisory-lookup", findings[0].Component.Name)
}
