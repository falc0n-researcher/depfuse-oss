package verdict_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/verdict"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestPrependEcosystemReceipt(t *testing.T) {
	comp := models.Component{Name: "next", Version: "15.1.0"}
	ctx := &models.PackageContext{
		Name:            "next",
		Description:     "The React Framework",
		WeeklyDownloads: 8_000_000,
		Popularity:      models.PopularityUbiquitous,
	}
	recs := verdict.PrependEcosystemReceipt(nil, comp, ctx)
	require.Len(t, recs, 1)
	require.Equal(t, models.ReceiptEcosystem, recs[0].Kind)
	require.Contains(t, recs[0].Claim, "next@15.1.0")
}
