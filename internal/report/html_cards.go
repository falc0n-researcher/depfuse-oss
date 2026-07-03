package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// RenderHTMLWriter writes a self-contained HTML report.
func RenderHTMLWriter(w io.Writer, result models.ScanResult) error {
	_, err := io.WriteString(w, buildHTMLPage(result))
	return err
}

// RenderHTML writes report.html to path.
func RenderHTML(path string, result models.ScanResult) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return RenderHTMLWriter(f, result)
}

func writeMetaItem(b *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(b, `<div class="meta-item"><label>%s</label><span>%s</span></div>`, esc(strings.ToUpper(label)), esc(value))
}

func writeKPI(b *strings.Builder, class, value, label, hint string) {
	fmt.Fprintf(b, `<div class="kpi %s"><div class="kpi-value">%s</div><div class="kpi-label">%s</div><div class="kpi-label">%s</div></div>`,
		class, esc(value), esc(strings.ToUpper(label)), esc(hint))
}

func writeFindingCard(b *strings.Builder, f models.Finding, packages map[string]models.PackageContext, showReceipts bool) {
	pri := f.Classification.Priority
	cardClass := "finding-card"
	if f.Verdict == models.VerdictFixNow || f.Verdict == models.VerdictPatchNow {
		cardClass += " action"
	} else if f.Verdict == models.VerdictFixSoon || f.Verdict == models.VerdictPatchSoon {
		cardClass += " soon"
	}

	cve := f.CveMatch.CVEID
	if cve == "" {
		cve = f.CveMatch.OSVID
	}
	advisory := f.CveMatch.GHSAID
	if advisory == "" {
		advisory = f.CveMatch.OSVID
	}

	pathLine := ""
	if chain := resolve.FormatDependencyPath(f.Component); chain != "" && (len(f.Component.Path) > 0 || f.Component.Direct) {
		pathLine = fmt.Sprintf(`<div class="finding-path">%s</div>`, esc(chain))
	}

	cveURL := cvePrimaryURL(f.CveMatch)
	cveTitle := esc(cve)
	if cveURL != "" {
		cveTitle = fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener" class="cve-link">%s</a>`, esc(cveURL), esc(cve))
	}

	fmt.Fprintf(b, `<article class="%s"><div class="finding-top">`, cardClass)
	fmt.Fprintf(b, `<div class="priority-pill %s">%s<span class="priority-sub">%s</span></div>`,
		priorityClass(pri), esc(pri.String()), esc(pri.Label()))
	fmt.Fprintf(b, `<div class="finding-title"><div class="finding-cve">%s</div>`, cveTitle)
	if advisory != "" && advisory != cve {
		fmt.Fprintf(b, `<div class="finding-advisory">%s</div>`, esc(advisory))
	}
	if desc := cveDescriptionHTML(f.CveMatch); desc != "" {
		b.WriteString(desc)
	}
	fmt.Fprintf(b, `<div class="finding-pkg-line"><strong>%s</strong>@<strong>%s</strong> · %s</div>`,
		esc(f.Component.Name), esc(f.Component.Version), esc(dependencyRoleLabel(f.Component)))
	b.WriteString(pathLine)
	fmt.Fprintf(b, `</div><span class="verdict-pill verdict-%s">%s</span></div>`, verdictClass(f.Verdict), esc(string(f.Verdict)))

	b.WriteString(`<div class="finding-body">`)
	b.WriteString(`<div class="signals-row">`)
	b.WriteString(signalsHTML(f))
	b.WriteString(`</div>`)
	b.WriteString(fixHTML(f))

	if showReceipts && len(f.Receipts) > 0 {
		b.WriteString(`<div class="receipts"><div class="receipts-title">Verdict Receipts</div><ul>`)
		for _, r := range f.Receipts {
			b.WriteString(`<li>`)
			b.WriteString(receiptBadgeHTML(r.Kind, r.URL))
			b.WriteString(` <span>` + esc(r.Claim) + `</span>`)
			if r.URL != "" {
				fmt.Fprintf(b, `<a href="%s" target="_blank" rel="noopener">source ↗</a>`, esc(r.URL))
			}
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ul></div>`)
	}
	b.WriteString(`</div></article>`)
}

func fixTableCell(f models.Finding) string {
	r := f.Remediation
	if r == nil || !r.FixAvailable {
		if len(f.CveMatch.FixedVersions) > 0 {
			return fmt.Sprintf(`<span class="ver-to" style="font-size:.75rem">≥ %s</span>`, esc(f.CveMatch.FixedVersions[0]))
		}
		return `<span class="dim">—</span>`
	}
	installed := r.Installed
	if installed == "" {
		installed = f.Component.Version
	}
	_, jumpLabel, _ := jumpMeta(r.Jump, r.Breaking)
	return fmt.Sprintf(`<span class="ver-from" style="font-size:.75rem">%s</span> → <span class="ver-to" style="font-size:.75rem">%s</span> <span class="dim">(%s)</span>`,
		esc(installed), esc(r.FixVersion), esc(jumpLabel))
}

func writeDeltaSection(b *strings.Builder, d *models.ScanDelta) {
	fmt.Fprintf(b, `<section class="section"><div class="section-head"><h2>Changes Since Last Scan</h2><span class="count">%s</span></div>`,
		esc(d.PreviousScanAt.UTC().Format(time.RFC3339)))
	writeDeltaBucket(b, "Escalated", d.Escalated)
	writeDeltaBucket(b, "De-escalated", d.Deescalated)
	writeDeltaBucket(b, "EPSS shifts", d.EPSSShifts)
	writeDeltaBucket(b, "New findings", d.NewFindings)
	writeDeltaBucket(b, "Removed", d.Removed)
	b.WriteString(`</section>`)
}

func writeDeltaBucket(b *strings.Builder, title string, items []models.FindingDelta) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, `<p style="margin:.5rem 0 .25rem;font-weight:600">%s (%d)</p><ul style="margin:0 0 1rem 1.25rem;font-size:.78rem">`, esc(strings.ToUpper(title)), len(items))
	for _, item := range items {
		cve := item.CVEID
		if cve == "" {
			cve = item.Key
		}
		fmt.Fprintf(b, `<li><strong>%s</strong> %s <span class="dim">%s</span></li>`, esc(cve), esc(item.Summary), esc(item.Package))
	}
	b.WriteString(`</ul>`)
}

func pkgmetaDownloadsLine(ctx *models.PackageContext) string {
	if ctx == nil {
		return ""
	}
	var parts []string
	if d := strings.TrimSpace(ctx.Description); d != "" {
		parts = append(parts, esc(pkgmetaSummaryTruncate(d, 80)))
	}
	if dl := pkgmeta.FormatWeeklyDownloads(ctx.WeeklyDownloads); dl != "" {
		parts = append(parts, esc(dl))
	}
	return strings.Join(parts, " · ")
}
