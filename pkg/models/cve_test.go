package models_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestCveMatchAdvisoryID(t *testing.T) {
	require.Equal(t, "CVE-2024-0001", models.CveMatch{CVEID: "CVE-2024-0001"}.AdvisoryID())
	require.Equal(t, "GHSA-xxxx-yyyy-zzzz", models.CveMatch{GHSAID: "GHSA-xxxx-yyyy-zzzz"}.AdvisoryID())
	require.Equal(t, "GHSA-abcd-efgh-ijkl", models.CveMatch{OSVID: "GHSA-abcd-efgh-ijkl"}.AdvisoryID())
	require.Equal(t, "CVE-2024-0002", models.CveMatch{Aliases: []string{"CVE-2024-0002"}}.AdvisoryID())
	require.Empty(t, models.CveMatch{}.AdvisoryID())
}
