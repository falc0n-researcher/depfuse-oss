package verdict_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/verdict"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestExposureReceiptTransitivePath(t *testing.T) {
	recs := verdict.BuildReceipts(models.Component{
		Name: "follow-redirects", Version: "1.15.4",
		Path: []string{"axios", "follow-redirects"},
	}, models.CveMatch{}, models.Classification{})
	require.NotEmpty(t, recs)
	last := recs[len(recs)-1]
	require.Equal(t, models.ReceiptDependencyPath, last.Kind)
	require.Contains(t, last.Claim, "axios → follow-redirects@1.15.4")
}

func TestExposureReceiptDirectLockfile(t *testing.T) {
	recs := verdict.BuildReceipts(models.Component{
		Name: "axios", Version: "1.6.0", Path: []string{"axios"},
	}, models.CveMatch{}, models.Classification{})
	require.NotEmpty(t, recs)
	last := recs[len(recs)-1]
	require.Equal(t, models.ReceiptExposure, last.Kind)
	require.Contains(t, last.Claim, "Lockfile confirms")
}
