package report

import (
	"fmt"
	"html"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func esc(s string) string { return html.EscapeString(s) }

func cveDescriptionHTML(c models.CveMatch) string {
	text := strings.TrimSpace(c.Summary)
	if text == "" {
		text = strings.TrimSpace(c.Details)
	} else if d := strings.TrimSpace(c.Details); d != "" && len(d) > len(text)+40 {
		text = text + " — " + pkgmetaSummaryTruncate(d, 220)
	}
	if text == "" {
		return ""
	}
	return fmt.Sprintf(`<p class="finding-cve-desc">%s</p>`, esc(pkgmetaSummaryTruncate(text, 320)))
}

func packageContextFor(f models.Finding, packages map[string]models.PackageContext) *models.PackageContext {
	if f.PackageContext != nil {
		copy := *f.PackageContext
		return &copy
	}
	if packages == nil {
		return nil
	}
	if ctx, ok := packages[f.Component.Name]; ok {
		copy := ctx
		return &copy
	}
	return nil
}

func fixHTML(f models.Finding) string {
	r := f.Remediation
	if r == nil {
		if len(f.CveMatch.FixedVersions) > 0 {
			ver := f.CveMatch.FixedVersions[0]
			if len(f.CveMatch.FixedVersions) > 1 {
				ver += "+"
			}
			return fmt.Sprintf(`<div class="fix-block"><div class="fix-label">Recommended fix</div>
<div class="fix-path"><span class="ver-to">%s</span><span class="fix-hint">Advisory fixed version — verify compatibility</span></div></div>`,
				esc(ver))
		}
		return `<div class="fix-block"><div class="fix-label">Remediation</div><div class="fix-path"><span class="jump-badge jump-none">No published fix</span><span class="fix-hint">Check advisory or remove dependency</span></div></div>`
	}

	if !r.FixAvailable {
		hint := "No fixed version published yet — pin, override, or remove"
		if r.Jump == models.JumpUnknown {
			hint = "See advisory for fixed branch"
		}
		return fmt.Sprintf(`<div class="fix-block"><div class="fix-label">Remediation</div>
<div class="fix-path"><span class="jump-badge jump-none">No fix available</span><span class="fix-hint">%s</span></div></div>`, esc(hint))
	}

	installed := r.Installed
	if installed == "" {
		installed = f.Component.Version
	}

	jumpClass, jumpLabel, hint := jumpMeta(r.Jump, r.Breaking)
	return fmt.Sprintf(`<div class="fix-block"><div class="fix-label">Upgrade path</div>
<div class="fix-path">
<span class="ver-from">%s</span><span class="ver-arrow">→</span><span class="ver-to">%s</span>
<span class="jump-badge %s">%s</span>
<span class="fix-hint">%s</span>
</div></div>`,
		esc(installed), esc(r.FixVersion), jumpClass, esc(jumpLabel), esc(hint))
}

func jumpMeta(jump models.UpgradeJump, breaking bool) (class, label, hint string) {
	switch jump {
	case models.JumpPatch:
		return "jump-patch", "Patch release", "Low risk — same major.minor line"
	case models.JumpMinor:
		return "jump-minor", "Minor release", "Review changelog — usually backward compatible"
	case models.JumpMajor:
		return "jump-major", "Major release", "Breaking changes likely — test thoroughly"
	default:
		if breaking {
			return "jump-major", "Major upgrade", "Breaking changes likely — test thoroughly"
		}
		return "jump-patch", "Upgrade", "Verify in staging before release"
	}
}

func linkedBadge(class, label, url string) string {
	if url != "" {
		return fmt.Sprintf(`<a class="badge %s badge-link" href="%s" target="_blank" rel="noopener">%s</a>`,
			class, esc(url), esc(label))
	}
	return fmt.Sprintf(`<span class="badge %s">%s</span>`, class, esc(label))
}

func signalURLMap(f models.Finding) map[string]string {
	urls := map[string]string{}
	add := func(key, url string) {
		if url != "" && urls[key] == "" {
			urls[key] = url
		}
	}
	for _, r := range f.Receipts {
		switch r.Kind {
		case models.ReceiptKEV:
			add("kev", r.URL)
		case models.ReceiptNuclei:
			add("nuclei", r.URL)
		case models.ReceiptMSF:
			add("msf", r.URL)
		case models.ReceiptEDB:
			add("edb", r.URL)
		case models.ReceiptPoC:
			add("poc", r.URL)
		}
	}
	for _, e := range f.Classification.Evidence {
		switch e.Source {
		case models.SourceKEV:
			add("kev", e.URL)
		case models.SourceNuclei:
			add("nuclei", e.URL)
		case models.SourceMetasploit:
			add("msf", e.URL)
		case models.SourceExploitDB:
			add("edb", e.URL)
		case models.SourcePoCGitHub, models.SourceVulnCheckXDB:
			add("poc", e.URL)
		}
	}
	return urls
}

func signalsHTML(f models.Finding) string {
	s := f.Classification.Signals
	if !s.KEV && !s.Nuclei && !s.Metasploit && !s.ExploitDB && !s.PoCPresent && s.EPSS <= 0 {
		return `<span class="dim">No exploit signals indexed</span>`
	}
	urls := signalURLMap(f)
	var parts []string
	if s.KEV {
		parts = append(parts, linkedBadge("badge-kev", "KEV", urls["kev"]))
	}
	if s.Nuclei {
		parts = append(parts, linkedBadge("badge-nuc", "Nuclei", urls["nuclei"]))
	}
	if s.Metasploit {
		parts = append(parts, linkedBadge("badge-msf", "Metasploit", urls["msf"]))
	}
	if s.ExploitDB {
		parts = append(parts, linkedBadge("badge-edb", "Exploit-DB", urls["edb"]))
	}
	if s.PoCPresent {
		parts = append(parts, linkedBadge("badge-poc", "PoC", urls["poc"]))
	}
	if s.EPSS > 0 {
		parts = append(parts, fmt.Sprintf(`<span class="badge badge-epss" title="EPSS %.2f">EPSS %.0f%%</span>`, s.EPSS, s.EPSS*100))
	}
	return strings.Join(parts, " ")
}

func receiptBadgeHTML(kind models.ReceiptKind, url string) string {
	switch kind {
	case models.ReceiptKEV:
		return linkedBadge("badge-kev", "KEV", url)
	case models.ReceiptNuclei:
		return linkedBadge("badge-nuc", "Nuclei", url)
	case models.ReceiptMSF:
		return linkedBadge("badge-msf", "MSF", url)
	case models.ReceiptEDB:
		return linkedBadge("badge-edb", "EDB", url)
	case models.ReceiptPoC:
		return linkedBadge("badge-poc", "PoC", url)
	case models.ReceiptEPSS:
		return linkedBadge("badge-epss", "EPSS", url)
	default:
		return linkedBadge("", kind.String(), url)
	}
}

func verdictClass(v models.Verdict) string {
	switch v {
	case models.VerdictFixNow, models.VerdictPatchNow:
		return "danger"
	case models.VerdictFixSoon, models.VerdictPatchSoon:
		return "warn"
	default:
		return "ok"
	}
}

func priorityClass(p models.Priority) string {
	return "priority-" + strings.ToLower(p.String())
}

func pkgmetaSummaryLine(ctx *models.PackageContext) string {
	return pkgmeta.SummaryLine(ctx)
}

func pkgmetaSummaryTruncate(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func writeDonutChart(b *strings.Builder, s models.ScanSummary) {
	counts := []int{s.P0, s.P1, s.P2, s.P3, s.P4}
	labels := []string{"P0", "P1", "P2", "P3", "P4"}
	colors := []string{"#dc2626", "#d97706", "#7c3aed", "#0284c7", "#94a3b8"}
	total := 0
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		total = 1
	}

	// SVG donut
	const cx, cy, r, stroke = 50.0, 50.0, 38.0, 14.0
	circ := 2 * 3.14159265 * r
	var offset float64
	var arcs strings.Builder
	for i, c := range counts {
		if c == 0 {
			continue
		}
		frac := float64(c) / float64(total)
		dash := circ * frac
		gap := circ - dash
		fmt.Fprintf(&arcs, `<circle cx="%.0f" cy="%.0f" r="%.0f" fill="none" stroke="%s" stroke-width="%.0f" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 %.0f %.0f)"/>`,
			cx, cy, r, colors[i], stroke, dash, gap, -offset, cx, cy)
		offset += dash
	}

	b.WriteString(`<div class="charts-row"><svg width="120" height="120" viewBox="0 0 100 100" aria-label="Priority distribution">`)
	fmt.Fprintf(b, `<circle cx="%.0f" cy="%.0f" r="%.0f" fill="none" stroke="#e2e8f0" stroke-width="%.0f"/>`, cx, cy, r, stroke)
	b.WriteString(arcs.String())
	fmt.Fprintf(b, `<text x="%.0f" y="%.0f" text-anchor="middle" font-family="%s,monospace" font-size="11" font-weight="700" fill="#0f172a">%d</text>`, cx, cy-2, reportFontName, total)
	fmt.Fprintf(b, `<text x="%.0f" y="%.0f" text-anchor="middle" font-family="%s,monospace" font-size="6" fill="#64748b">findings</text>`, cx, cy+8, reportFontName)
	b.WriteString(`</svg><div class="chart-legend">`)
	for i, c := range counts {
		if c == 0 {
			continue
		}
		fmt.Fprintf(b, `<div class="legend-item"><span class="legend-dot" style="background:%s"></span><span>%s · %s</span><span class="legend-count">%d</span></div>`,
			colors[i], esc(labels[i]), esc(priorityLabelShort(models.Priority(i))), c)
	}
	b.WriteString(`</div></div>`)
}

func priorityLabelShort(p models.Priority) string {
	switch p {
	case models.PriorityP0:
		return "Exploited"
	case models.PriorityP1:
		return "Weaponized"
	case models.PriorityP2:
		return "PoC"
	case models.PriorityP3:
		return "Watch"
	default:
		return "Quiet"
	}
}

func writeVerdictBars(b *strings.Builder, s models.ScanSummary, total int) {
	if total == 0 {
		total = 1
	}
	rows := []struct {
		label, class string
		count        int
	}{
		{"Fix Now", "bar-fix-now", s.FixNow},
		{"Fix Soon", "bar-fix-soon", s.FixSoon},
		{"OK", "bar-ok", s.OK},
		{"Weaponized Exposure", "bar-weaponized", s.WeaponizedExposure()},
	}
	b.WriteString(`<div class="verdict-bars">`)
	for _, row := range rows {
		if row.count == 0 {
			continue
		}
		pct := float64(row.count) / float64(total) * 100
		fmt.Fprintf(b, `<div class="verdict-bar-row"><span>%s</span><div class="verdict-bar-track"><div class="verdict-bar-fill %s" style="width:%.1f%%"></div></div><span>%d</span></div>`,
			esc(row.label), row.class, pct, row.count)
	}
	b.WriteString(`</div>`)
}

func filterHTMLFindings(in []models.Finding, fn func(models.Finding) bool) []models.Finding {
	var out []models.Finding
	for _, f := range in {
		if fn(f) {
			out = append(out, f)
		}
	}
	return out
}
