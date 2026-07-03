package rollup

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestBuildUpgradeRollupGroupsByDirectRoot(t *testing.T) {
	components := []models.Component{
		{Name: "express", Version: "4.17.1", Direct: true},
		{Name: "qs", Version: "6.7.0", Path: []string{"express", "body-parser"}},
	}
	findings := []models.Finding{
		{
			Component:      components[1],
			Classification: models.Classification{Priority: models.PriorityP2},
			CveMatch:       models.CveMatch{CVEID: "CVE-2022-24999", FixedVersions: []string{"6.9.7"}},
		},
		{
			Component:      models.Component{Name: "next", Version: "15.1.0", Direct: true},
			Classification: models.Classification{Priority: models.PriorityP0},
			Remediation:    &models.Remediation{FixAvailable: true, FixVersion: "15.2.3"},
		},
	}
	rollups := BuildUpgradeRollup(components, findings)
	require.Len(t, rollups, 2)
	require.Equal(t, "next", rollups[0].RootName)
	require.Equal(t, 1, rollups[0].FindingCount)
	require.Equal(t, "15.2.3", rollups[0].FixVersion)
}
