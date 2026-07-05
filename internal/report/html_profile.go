package report

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func writePackageEcoPills(b *strings.Builder, ctx *models.PackageContext) {
	if ctx == nil {
		return
	}
	var pills []string
	if dl := pkgmeta.FormatWeeklyDownloads(ctx.WeeklyDownloads); dl != "" {
		pills = append(pills, fmt.Sprintf(`<span class="stat-pill stat-pill-dl stat-pill-dl-primary">%s</span>`, esc(dl)))
	}
	if pop := pkgmeta.PopularityLabel(ctx.Popularity); pop != "" {
		pills = append(pills, fmt.Sprintf(`<span class="stat-pill stat-pill-pop">%s</span>`, esc(pop)))
	}
	if ctx.License != "" {
		pills = append(pills, fmt.Sprintf(`<span class="stat-pill stat-pill-lic">%s</span>`, esc(ctx.License)))
	}
	if ctx.Homepage != "" {
		pills = append(pills, fmt.Sprintf(`<a class="stat-pill stat-pill-link" href="%s" target="_blank" rel="noopener">Homepage ↗</a>`, esc(ctx.Homepage)))
	}
	if len(pills) == 0 {
		return
	}
	b.WriteString(`<div class="pkg-stats">`)
	for _, p := range pills {
		b.WriteString(p)
	}
	b.WriteString(`</div>`)
}

func writePackageEcoPillsCompact(b *strings.Builder, ctx *models.PackageContext) {
	if ctx == nil {
		return
	}
	if dl := pkgmeta.FormatWeeklyDownloads(ctx.WeeklyDownloads); dl != "" {
		fmt.Fprintf(b, `<span class="accord-pill accord-pill-dl">%s</span>`, esc(dl))
	}
	if ctx.License != "" {
		fmt.Fprintf(b, `<span class="accord-pill accord-pill-lic">%s</span>`, esc(ctx.License))
	}
}

func popularityBadge(ctx *models.PackageContext) string {
	if ctx == nil {
		return ""
	}
	switch ctx.Popularity {
	case models.PopularityUbiquitous:
		return `<span class="eco-badge eco-badge-hot">Ubiquitous</span>`
	case models.PopularityWidelyUsed:
		return `<span class="eco-badge eco-badge-wide">Widely used</span>`
	case models.PopularityPopular:
		return `<span class="eco-badge eco-badge-pop">Popular</span>`
	default:
		return ""
	}
}

func writePackageProfile(b *strings.Builder, name, version string, ctx *models.PackageContext) {
	if ctx == nil && name == "" {
		return
	}
	fmt.Fprintf(b, `<div class="pkg-profile">`)
	b.WriteString(`<div class="pkg-profile-head">`)
	b.WriteString(`<span class="pkg-profile-icon" aria-hidden="true">◈</span>`)
	b.WriteString(`<div class="pkg-profile-title">`)
	if name != "" {
		fmt.Fprintf(b, `<span class="pkg-profile-name">%s</span>`, esc(name))
		if version != "" {
			fmt.Fprintf(b, `<span class="pkg-profile-ver">@%s</span>`, esc(version))
		}
	}
	b.WriteString(`</div>`)
	if badge := popularityBadge(ctx); badge != "" {
		b.WriteString(badge)
	}
	b.WriteString(`</div>`)
	if ctx != nil {
		if desc := strings.TrimSpace(ctx.Description); desc != "" {
			fmt.Fprintf(b, `<p class="pkg-profile-desc">%s</p>`, esc(pkgmetaSummaryTruncate(desc, 240)))
		}
		writePackageEcoPills(b, ctx)
	}
	b.WriteString(`</div>`)
}

func writePackageContextBlock(b *strings.Builder, ctx *models.PackageContext) {
	if ctx == nil {
		return
	}
	writePackageProfile(b, ctx.Name, "", ctx)
}

func writeFindingEcoStrip(b *strings.Builder, f models.Finding, packages map[string]models.PackageContext) {
	ctx := packageContextFor(f, packages)
	if ctx == nil {
		return
	}
	b.WriteString(`<div class="finding-eco-strip">`)
	writePackageEcoPills(b, ctx)
	b.WriteString(`</div>`)
}
