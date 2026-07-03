package report

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/semver"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

type packageFixSuggestion struct {
	FixVersion string
	Worst      models.Priority
	Label      string
}

func packageFixSuggestionFor(findings []models.Finding) packageFixSuggestion {
	out := packageFixSuggestion{Worst: models.PriorityP4, Label: "See advisory"}
	for _, f := range findings {
		if f.Classification.Priority < out.Worst {
			out.Worst = f.Classification.Priority
		}
		if fix := rollupBestFix(f); fix != "" {
			out.FixVersion = maxFixStr(out.FixVersion, fix)
		}
	}
	if out.FixVersion != "" {
		out.Label = "≥ " + out.FixVersion
	}
	return out
}

func rollupBestFix(f models.Finding) string {
	if f.Remediation != nil && f.Remediation.FixAvailable && f.Remediation.FixVersion != "" {
		return f.Remediation.FixVersion
	}
	if len(f.CveMatch.FixedVersions) > 0 {
		return f.CveMatch.FixedVersions[0]
	}
	return ""
}

func maxFixStr(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if semver.CompareStr(b, a) > 0 {
		return b
	}
	return a
}

func writeCoverageBanner(b *strings.Builder, cov *models.ScanCoverageMeta) {
	if cov == nil || cov.Status == "complete" {
		return
	}
	class := "coverage-partial"
	if cov.IsIncomplete() {
		class = "coverage-incomplete"
	}
	fmt.Fprintf(b, `<div class="coverage-banner %s"><strong>%s</strong><span>%s</span></div>`,
		class, esc(strings.ToUpper(cov.Status)), esc(cov.Message))
}

func writePackageDossierFindings(b *strings.Builder, findings []models.Finding, packages map[string]models.PackageContext) {
	if len(findings) == 0 {
		return
	}
	sorted := append([]models.Finding{}, findings...)
	sortFindingsByPriority(sorted)
	fix := packageFixSuggestionFor(sorted)

	b.WriteString(`<section class="section"><div class="section-head"><h2>Vulnerabilities</h2>`)
	fmt.Fprintf(b, `<span class="count">%d CVE matches · one upgrade path</span></div>`, len(sorted))

	b.WriteString(`<div class="dossier-upgrade-card">`)
	fmt.Fprintf(b, `<div class="dossier-upgrade-head"><span class="priority-pill %s">%s</span>`,
		priorityClass(fix.Worst), esc(fix.Worst.String()))
	fmt.Fprintf(b, `<span class="dossier-upgrade-fix"><span class="rollup-fix-label">Suggested upgrade</span><span class="ver-to">%s</span></span></div>`,
		esc(fix.Label))
	b.WriteString(`<p class="dossier-upgrade-note dim">Upgrade this package once to address all listed advisories below.</p></div>`)

	b.WriteString(`<div class="table-wrap dossier-cve-table"><table class="cve-catalog dossier-cve-list"><thead><tr>
<th>Priority</th><th>CVE / Advisory</th><th>Summary</th><th>Fix</th><th>Verdict</th>
</tr></thead><tbody>`)
	for _, f := range sorted {
		writeDossierCVERow(b, f)
	}
	b.WriteString(`</tbody></table></div></section>`)
}

func writeDossierCVERow(b *strings.Builder, f models.Finding) {
	adv := advisoryID(f)
	summary := strings.TrimSpace(f.CveMatch.Summary)
	if summary == "" {
		summary = strings.TrimSpace(f.CveMatch.Details)
	}
	if summary == "" {
		summary = "—"
	}
	fix := formatFixCell(f)
	fmt.Fprintf(b, `<tr><td><span class="priority-pill %s">%s</span></td><td>%s</td><td class="summary-cell">%s</td><td>%s</td><td>%s</td></tr>`,
		priorityClass(f.Classification.Priority), esc(f.Classification.Priority.String()),
		esc(adv), esc(truncateText(summary, 120)), fix, esc(string(f.Verdict)))
}

func formatFixCell(f models.Finding) string {
	if f.Remediation != nil && f.Remediation.FixAvailable {
		return esc(f.Remediation.UpgradeLine(f.Component.Name))
	}
	if len(f.CveMatch.FixedVersions) > 0 {
		return esc("≥ " + f.CveMatch.FixedVersions[0])
	}
	return `<span class="dim">—</span>`
}

func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
