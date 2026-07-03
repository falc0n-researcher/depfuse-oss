package report

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/rollup"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func writeUpgradeRollupSection(b *strings.Builder, rollups []rollup.UpgradeRollup) {
	if len(rollups) == 0 {
		return
	}
	totalFindings := 0
	for _, r := range rollups {
		totalFindings += r.FindingCount
	}
	b.WriteString(`<section class="section"><div class="section-head"><h2>Priority Upgrades</h2>`)
	fmt.Fprintf(b, `<span class="count">%d declared deps · %d findings</span></div>`, len(rollups), totalFindings)
	b.WriteString(`<p class="page-lead">Upgrade these declared dependencies to clear the most vulnerability matches.</p>`)
	b.WriteString(`<div class="rollup-grid">`)
	for _, r := range rollups {
		root := r.RootName
		if r.RootVersion != "" {
			root += "@" + r.RootVersion
		}
		fix := "See advisory"
		if r.FixVersion != "" {
			fix = "≥ " + r.FixVersion
		}
		fmt.Fprintf(b, `<div class="rollup-card"><div class="rollup-head"><span class="rollup-pkg">%s</span><span class="priority-pill %s">%s</span></div>`,
			esc(root), priorityClass(r.Worst), esc(r.Worst.String()))
		fmt.Fprintf(b, `<div class="rollup-stats"><span>%d CVE matches</span><span>%d packages affected</span></div>`,
			r.FindingCount, r.PackageCount)
		fmt.Fprintf(b, `<div class="rollup-fix"><span class="rollup-fix-label">Suggested upgrade</span><span class="ver-to">%s</span></div>`, esc(fix))
		if len(r.Packages) > 0 && r.PackageCount > 1 {
			fmt.Fprintf(b, `<div class="rollup-affected dim">Includes %s</div>`, esc(strings.Join(truncateList(r.Packages, 5), ", ")))
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></section>`)
}

func writeAcceptedRiskSection(b *strings.Builder, accepted []models.Finding) {
	if len(accepted) == 0 {
		return
	}
	b.WriteString(`<section class="section section-decisions"><div class="section-head"><h2>Accepted Risk</h2>`)
	fmt.Fprintf(b, `<span class="count">%d suppressed by decision memory</span></div>`, len(accepted))
	b.WriteString(`<p class="page-lead">These findings are hidden from priority actions until exploit evidence moves. Reopens when: `)
	b.WriteString(esc(strings.Join(models.ReopenPolicyLabels(), ", ")))
	b.WriteString(`.</p><div class="decision-list">`)
	for _, f := range accepted {
		cve := f.CveMatch.CVEID
		if cve == "" {
			cve = f.CveMatch.GHSAID
		}
		reason := strings.TrimSpace(f.DecisionReason)
		if reason == "" {
			reason = "accepted-risk"
		}
		fmt.Fprintf(b, `<div class="decision-row"><div class="decision-main"><strong>%s</strong> · %s@%s</div>`,
			esc(cve), esc(f.Component.Name), esc(f.Component.Version))
		fmt.Fprintf(b, `<div class="decision-reason dim">%s</div></div>`, esc(reason))
	}
	b.WriteString(`</div></section>`)
}

func truncateList(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	out := append([]string{}, items[:max]...)
	out = append(out, fmt.Sprintf("+%d more", len(items)-max))
	return out
}
