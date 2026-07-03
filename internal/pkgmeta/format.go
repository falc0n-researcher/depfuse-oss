package pkgmeta

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const (
	weeklyUbiquitous = 10_000_000
	weeklyWidelyUsed = 1_000_000
	weeklyPopular    = 100_000
	weeklyModerate   = 10_000
)

// PopularityFromWeeklyDownloads maps npm weekly download counts to a tier label.
func PopularityFromWeeklyDownloads(weekly int64) models.PackagePopularity {
	switch {
	case weekly >= weeklyUbiquitous:
		return models.PopularityUbiquitous
	case weekly >= weeklyWidelyUsed:
		return models.PopularityWidelyUsed
	case weekly >= weeklyPopular:
		return models.PopularityPopular
	case weekly >= weeklyModerate:
		return models.PopularityModerate
	default:
		return models.PopularityNiche
	}
}

// PopularityLabel returns human-readable popularity text.
func PopularityLabel(p models.PackagePopularity) string {
	switch p {
	case models.PopularityUbiquitous:
		return "ubiquitous on npm"
	case models.PopularityWidelyUsed:
		return "widely used on npm"
	case models.PopularityPopular:
		return "popular on npm"
	case models.PopularityModerate:
		return "moderate adoption on npm"
	case models.PopularityNiche:
		return "niche on npm"
	default:
		return ""
	}
}

// FormatWeeklyDownloads renders download counts for CLI output.
func FormatWeeklyDownloads(n int64) string {
	if n <= 0 {
		return ""
	}
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("~%.1fB downloads/week", float64(n)/1_000_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("~%.1fM downloads/week", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("~%.1fk downloads/week", float64(n)/1_000)
	default:
		return fmt.Sprintf("~%d downloads/week", n)
	}
}

// ReceiptClaim builds the ecosystem exposure receipt line for a pinned package.
func ReceiptClaim(comp models.Component, ctx *models.PackageContext) string {
	if ctx == nil {
		return ""
	}
	parts := []string{fmt.Sprintf("%s@%s", comp.Name, comp.Version)}
	if label := PopularityLabel(ctx.Popularity); label != "" && ctx.WeeklyDownloads > 0 {
		parts = append(parts, fmt.Sprintf("is %s (%s)", label, FormatWeeklyDownloads(ctx.WeeklyDownloads)))
	} else if label := PopularityLabel(ctx.Popularity); label != "" {
		parts = append(parts, "is "+label)
	} else if dl := FormatWeeklyDownloads(ctx.WeeklyDownloads); dl != "" {
		parts = append(parts, dl+" on npm")
	}
	if desc := strings.TrimSpace(ctx.Description); desc != "" {
		parts = append(parts, "— "+truncate(desc, 80))
	}
	return strings.Join(parts, " ")
}

// SummaryLine is a compact one-line package context for headers.
func SummaryLine(ctx *models.PackageContext) string {
	if ctx == nil {
		return ""
	}
	var parts []string
	if dl := FormatWeeklyDownloads(ctx.WeeklyDownloads); dl != "" {
		parts = append(parts, dl)
	}
	if label := PopularityLabel(ctx.Popularity); label != "" {
		parts = append(parts, label)
	}
	if desc := strings.TrimSpace(ctx.Description); desc != "" {
		parts = append(parts, truncate(desc, 100))
	}
	return strings.Join(parts, " · ")
}

func truncate(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
