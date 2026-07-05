package report

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/inventory"
	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/internal/rollup"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func writeDashboard(b *strings.Builder, result models.ScanResult, data dashboardData) {
	meta := result.Meta
	s := result.Summary

	b.WriteString(`<div class="dash">`)

	// ── Top bar ──
	b.WriteString(`<header class="dash-header">`)
	b.WriteString(`<div class="dash-header-left">`)
	b.WriteString(`<div class="dash-logo"><span class="brand-mark">◆</span> Depfuse</div>`)
	b.WriteString(`<div class="dash-tagline">` + reportSubtitle + `</div>`)
	b.WriteString(`</div>`)
	b.WriteString(`<div class="dash-header-meta">`)
	if meta.InputPath != "" {
		fmt.Fprintf(b, `<span class="meta-chip"><label>Project</label>%s</span>`, esc(meta.InputPath))
	}
	fmt.Fprintf(b, `<span class="meta-chip"><label>Scanned</label>%s</span>`, esc(meta.Timestamp.UTC().Format("2 Jan 2006 · 15:04 UTC")))
	if meta.SnapshotVersion != "" {
		fmt.Fprintf(b, `<span class="meta-chip"><label>Intel</label>%s</span>`, esc(meta.SnapshotVersion))
	}
	if meta.DependencyTree != nil {
		dt := meta.DependencyTree
		fmt.Fprintf(b, `<span class="meta-chip"><label>Deps</label>%d (%d direct · %d nested)</span>`,
			dt.Total, dt.Direct, dt.Transitive)
	}
	if meta.PackageContext != nil {
		if line := pkgmetaSummaryLine(meta.PackageContext); line != "" {
			fmt.Fprintf(b, `<span class="meta-chip meta-chip-wide"><label>Package</label>%s</span>`, esc(line))
		}
	}
	fmt.Fprintf(b, `<span class="meta-chip meta-chip-accent"><label>Findings</label>%d</span>`, meta.FindingCount)
	b.WriteString(`</div></header>`)

	if meta.Coverage != nil {
		writeCoverageBanner(b, meta.Coverage)
	}

	// ── KPI strip ──
	b.WriteString(`<div class="dash-kpis">`)
	writeDashKPI(b, "kpi-danger", fmt.Sprint(s.Exploitable()), "Exploitable", "P0 + P1")
	writeDashKPI(b, "kpi-alert", fmt.Sprint(s.FixNow), "Fix Now", "Block release")
	writeDashKPI(b, "kpi-warn", fmt.Sprint(s.FixSoon), "Fix Soon", "Plan fix")
	writeDashKPI(b, "kpi-ok", fmt.Sprint(s.OK), "OK", "No action")
	writeDashKPI(b, "kpi-muted", fmt.Sprint(s.Total), "Total CVEs", "All matches")
	writeDashKPI(b, "kpi-muted", fmt.Sprint(meta.ComponentCount), "Packages", "In scope")
	b.WriteString(`</div>`)

	// ── Main grid: actions + chart ──
	b.WriteString(`<div class="dash-row">`)
	b.WriteString(`<section class="dash-panel dash-panel-wide" id="actions">`)
	b.WriteString(`<div class="panel-head"><h2>Priority Actions</h2>`)
	actionItems := filterHTMLFindings(result.Findings, func(f models.Finding) bool {
		if f.Reopened {
			return true
		}
		return f.Verdict == models.VerdictFixNow || f.Verdict == models.VerdictFixSoon
	})
	fmt.Fprintf(b, `<span class="panel-count">%d</span></div>`, len(actionItems))
	if len(actionItems) == 0 {
		b.WriteString(`<p class="empty-state">No priority actions — all findings within acceptable risk.</p>`)
	} else {
		b.WriteString(`<div class="action-cards">`)
		for _, f := range actionItems {
			writeFindingCard(b, f, result.Packages, true)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</section>`)

	b.WriteString(`<section class="dash-panel" id="distribution">`)
	b.WriteString(`<div class="panel-head"><h2>Distribution</h2></div>`)
	writeDonutChart(b, s)
	writeVerdictBars(b, s, maxInt(s.Total, 1))
	b.WriteString(`</section></div>`)

	if result.Delta != nil && result.Delta.HasChanges() {
		writeDeltaSection(b, result.Delta)
	}

	rollups := rollup.BuildUpgradeRollup(result.Components, append(append([]models.Finding{}, result.Findings...), result.Accepted...))
	writeUpgradeRollupSection(b, rollups, result.Packages)
	if len(result.Accepted) > 0 {
		writeAcceptedRiskSection(b, result.Accepted)
	}

	// ── Findings table ──
	b.WriteString(`<section class="dash-panel dash-panel-full" id="findings">`)
	b.WriteString(`<div class="panel-head"><h2>All Findings</h2>`)
	fmt.Fprintf(b, `<span class="panel-count">%d matches · %d packages</span></div>`, s.Total, countPackagesWithCVE(data.Packages))
	all := append([]models.Finding{}, result.Findings...)
	if result.ShowIgnored {
		all = append(all, result.Suppressed...)
	}
	sortFindingsByPriority(all)
	writeFindingsTable(b, all, data)
	b.WriteString(`</section>`)

	// ── Dependency tree ──
	if len(result.Components) > 0 {
		b.WriteString(`<section class="dash-panel dash-panel-full" id="tree">`)
		b.WriteString(`<div class="panel-head"><h2>Dependency Tree</h2></div>`)
		allFindings := append([]models.Finding{}, result.Findings...)
		tree := inventory.BuildTree(result.Components, allFindings)
		writeDepTreeSummary(b, tree.Stats)
		writeDepTreeToolbar(b)
		if len(tree.Roots) == 0 && len(tree.Orphans) == 0 {
			b.WriteString(`<p class="empty-state">No dependency tree available.</p>`)
		} else {
			opts := depTreeRenderOpts{compact: false, maxFlatDepth: 2}
			writeDepForest(b, tree.Roots, opts)
			writeDepOrphans(b, tree.Orphans)
		}
		b.WriteString(depTreeFilterScript)
		b.WriteString(`</section>`)
	}

	// ── Package accordions ──
	if len(data.Packages) > 0 {
		b.WriteString(`<section class="dash-panel dash-panel-full" id="packages">`)
		b.WriteString(`<div class="panel-head"><h2>Packages</h2>`)
		fmt.Fprintf(b, `<span class="panel-count">%d</span></div>`, len(data.Packages))
		writePackageAccordions(b, data.Packages, result.Packages)
		b.WriteString(`</section>`)
	}

	b.WriteString(`<footer class="dash-footer">Generated by Depfuse · ` + reportTagline + `</footer>`)
	b.WriteString(`</div>`)
}

func writeDashKPI(b *strings.Builder, class, value, label, hint string) {
	fmt.Fprintf(b, `<div class="dash-kpi %s"><div class="dash-kpi-value">%s</div><div class="dash-kpi-label">%s</div><div class="dash-kpi-hint">%s</div></div>`,
		class, esc(value), esc(label), esc(hint))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func writeFindingsTable(b *strings.Builder, findings []models.Finding, data dashboardData) {
	slugByKey := map[string]string{}
	for _, p := range data.Packages {
		slugByKey[p.Key] = p.Slug
	}

	b.WriteString(`<div class="table-wrap"><table class="findings-table"><thead><tr>
<th>Priority</th><th>CVE / Advisory</th><th>Package</th><th>Path</th><th>Signals</th><th>Fix</th><th>Verdict</th>
</tr></thead><tbody>`)

	for _, f := range findings {
		pri := f.Classification.Priority
		adv := advisoryID(f)
		cveURL := cvePrimaryURL(f.CveMatch)
		advCell := esc(adv)
		if cveURL != "" {
			advCell = fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener" class="cve-link">%s</a>`, esc(cveURL), esc(adv))
		}

		pkgKey := f.Component.Name + "@" + f.Component.Version
		pkgCell := fmt.Sprintf(`%s@%s`, esc(f.Component.Name), esc(f.Component.Version))
		if slug, ok := slugByKey[pkgKey]; ok {
			pkgCell = fmt.Sprintf(`<a href="#pkg-%s" class="pkg-link">%s</a>`, esc(slug), esc(f.Component.Name+"@"+f.Component.Version))
		}

		path := resolve.FormatDependencyPath(f.Component)
		if path == "" {
			path = "—"
		}

		fmt.Fprintf(b, `<tr><td><span class="priority-pill %s">%s</span></td>`,
			priorityClass(pri), esc(pri.String()))
		fmt.Fprintf(b, `<td>%s</td><td>%s</td><td class="path-cell">%s</td><td>%s</td><td>%s</td>`,
			advCell, pkgCell, esc(path), signalsHTML(f), fixTableCell(f))
		fmt.Fprintf(b, `<td><span class="verdict-pill verdict-%s">%s</span></td></tr>`,
			verdictClass(f.Verdict), esc(string(f.Verdict)))
	}
	b.WriteString(`</tbody></table></div>`)
}

func writePackageAccordions(b *strings.Builder, packages []packagePageData, ctx map[string]models.PackageContext) {
	for _, pkg := range packages {
		writePackageAccordion(b, pkg, ctx)
	}
}

func writePackageAccordion(b *strings.Builder, pkg packagePageData, packages map[string]models.PackageContext) {
	cveBadge := `<span class="accord-badge accord-ok">Clean</span>`
	if pkg.CVECount > 0 {
		cveBadge = fmt.Sprintf(`<span class="accord-badge %s">%s · %d CVE</span>`,
			priorityClass(pkg.Worst), esc(pkg.Worst.String()), pkg.CVECount)
	}

	fmt.Fprintf(b, `<details class="pkg-accord" id="pkg-%s">`, esc(pkg.Slug))
	fmt.Fprintf(b, `<summary class="pkg-accord-summary"><span class="accord-name">%s</span><span class="accord-ver">@%s</span>`,
		esc(pkg.Name), esc(pkg.Version))
	ctx := pkg.Context
	if ctx == nil {
		if c, ok := packages[pkg.Name]; ok {
			copy := c
			ctx = &copy
		}
	}
	if ctx != nil {
		b.WriteString(`<span class="accord-eco">`)
		writePackageEcoPillsCompact(b, ctx)
		b.WriteString(`</span>`)
	}
	fmt.Fprintf(b, `%s`, cveBadge)
	if pkg.Shadow > 0 {
		fmt.Fprintf(b, `<span class="accord-shadow">%d nested</span>`, pkg.Shadow)
	}
	b.WriteString(`</summary><div class="pkg-accord-body">`)

	writePackageProfile(b, pkg.Name, pkg.Version, ctx)

	b.WriteString(`<div class="pkg-accord-meta">`)
	writeDossierMeta(b, "Role", dependencyRoleLabel(pkg.Component))
	if pkg.CVECount > 0 {
		writeDossierMeta(b, "Vulnerabilities", fmt.Sprintf("%d matches · worst %s", pkg.CVECount, pkg.Worst.String()))
	}
	if len(pkg.Component.Path) > 0 {
		writeDossierMeta(b, "Path", strings.Join(pkg.Component.Path, " → "))
	}
	b.WriteString(`</div>`)

	if len(pkg.Findings) > 0 {
		writePackageDossierFindings(b, pkg.Findings, packages)
	}

	if pkg.Node != nil && len(pkg.Node.Children) > 0 {
		b.WriteString(`<div class="pkg-accord-tree">`)
		writeDepSubtree(b, pkg.Node)
		b.WriteString(`</div>`)
	}

	b.WriteString(`</div></details>`)
}

func writeDossierMeta(b *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(b, `<div class="dossier-meta-item"><label>%s</label><span>%s</span></div>`, esc(strings.ToUpper(label)), esc(value))
}
