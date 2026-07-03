package pkgmeta_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestPopularityFromWeeklyDownloads(t *testing.T) {
	require.Equal(t, models.PopularityUbiquitous, pkgmeta.PopularityFromWeeklyDownloads(12_000_000))
	require.Equal(t, models.PopularityWidelyUsed, pkgmeta.PopularityFromWeeklyDownloads(2_000_000))
	require.Equal(t, models.PopularityPopular, pkgmeta.PopularityFromWeeklyDownloads(250_000))
	require.Equal(t, models.PopularityModerate, pkgmeta.PopularityFromWeeklyDownloads(25_000))
	require.Equal(t, models.PopularityNiche, pkgmeta.PopularityFromWeeklyDownloads(100))
}

func TestFormatWeeklyDownloads(t *testing.T) {
	require.Equal(t, "~8.2M downloads/week", pkgmeta.FormatWeeklyDownloads(8_200_000))
	require.Equal(t, "", pkgmeta.FormatWeeklyDownloads(0))
}

func TestReceiptClaim(t *testing.T) {
	claim := pkgmeta.ReceiptClaim(models.Component{Name: "next", Version: "15.1.0"}, &models.PackageContext{
		Name:            "next",
		Description:     "The React Framework",
		WeeklyDownloads: 8_200_000,
		Popularity:      models.PopularityUbiquitous,
	})
	require.Contains(t, claim, "next@15.1.0")
	require.Contains(t, claim, "ubiquitous")
	require.Contains(t, claim, "React Framework")
}
