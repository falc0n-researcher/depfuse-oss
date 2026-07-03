package ui

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/internal/rollup"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/mattn/go-runewidth"
)

// FormatSignals returns compact, styled signal badges.
func FormatSignals(w io.Writer, s models.Signals) string {
	if !s.KEV && !s.Nuclei && !s.Metasploit && !s.ExploitDB && !s.PoCPresent && s.EPSS <= 0 {
		return Dim(w, "—")
	}
	var parts []string
	if s.KEV {
		parts = append(parts, badge(w, "KEV", red))
	}
	if s.Nuclei {
		parts = append(parts, badge(w, "Nuc", orange))
	}
	if s.Metasploit {
		parts = append(parts, badge(w, "MSF", yellow))
	}
	if s.ExploitDB {
		parts = append(parts, badge(w, "EDB", yellow))
	}
	if s.PoCPresent {
		parts = append(parts, badge(w, "PoC", cyan))
	}
	if s.EPSS > 0 {
		parts = append(parts, epssBadge(w, s.EPSS))
	}
	return strings.Join(parts, " ")
}

func badge(w io.Writer, label, color string) string {
	switch color {
	case red:
		return badgeStyled(w, label, styleBadgeKEV)
	case orange:
		return badgeStyled(w, label, styleBadgeNuc)
	case yellow:
		return badgeStyled(w, label, styleBadgeMSF)
	case cyan:
		return badgeStyled(w, label, styleBadgePoC)
	default:
		return label
	}
}

func epssBadge(w io.Writer, score float64) string {
	bar := ProgressBar(8, score, "█", "░")
	label := fmt.Sprintf("EPSS %.2f", score)
	if !Color(w) {
		return bar + " " + label
	}
	c := green
	if score >= 0.5 {
		c = orange
	}
	if score >= 0.85 {
		c = red
	}
	return dim + bar + reset + " " + c + label + reset
}

// VulnColumns splits a match into advisory + CVE columns.
func VulnColumns(w io.Writer, c models.CveMatch) (advisory, cve string) {
	cve = canonicalCVE(c)
	switch {
	case c.GHSAID != "":
		advisory = c.GHSAID
	case npmAdvisoryID(c) != "":
		advisory = npmAdvisoryID(c)
	case strings.HasPrefix(c.CVEID, "GHSA-"):
		advisory = c.CVEID
	case strings.HasPrefix(c.OSVID, "GHSA-"):
		advisory = c.OSVID
	case strings.HasPrefix(c.CVEID, "NPM-"):
		advisory = c.CVEID
	case strings.HasPrefix(c.OSVID, "NPM-"):
		advisory = c.OSVID
	}
	if cve == "" {
		if strings.HasPrefix(c.CVEID, "CVE-") {
			cve = c.CVEID
		} else if advisory == "" {
			cve = firstNonEmpty(c.CVEID, c.OSVID)
		}
	}
	if advisory == "" {
		advisory = Dim(w, "—")
	}
	return advisory, cve
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func canonicalCVE(c models.CveMatch) string {
	if strings.HasPrefix(c.CVEID, "CVE-") {
		return c.CVEID
	}
	for _, a := range c.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return ""
}

func npmAdvisoryID(c models.CveMatch) string {
	for _, a := range c.Aliases {
		if strings.HasPrefix(a, "NPM-") {
			return a
		}
	}
	return ""
}

// RenderScan writes the rich terminal scan report.
func RenderScan(w io.Writer, result models.ScanResult) {

	MetaLine(w, "Snapshot", fmt.Sprintf("%s  %s", result.Meta.SnapshotVersion, Dim(w, "("+result.Meta.SnapshotHash+")")))
	if result.Meta.InputPath != "" {
		MetaLine(w, "Input", result.Meta.InputPath)
	}
	if result.Meta.ResolvedPackage != "" {
		MetaLine(w, "Resolved", result.Meta.ResolvedPackage)
	}
	if dt := result.Meta.DependencyTree; dt != nil && dt.Transitive > 0 {
		MetaLine(w, "Dependency tree", fmt.Sprintf("%d packages (%d direct · %d transitive)",
			dt.Total, dt.Direct, dt.Transitive))
	}
	renderPackageContextHeader(w, result.Meta.PackageContext)
	MetaLine(w, "Scope", fmt.Sprintf("%d packages · %d findings · %dms",
		result.Meta.ComponentCount, result.Meta.FindingCount, result.Meta.DurationMS))
	if result.Meta.PackageNote != "" {
		fmt.Fprintf(w, "  %s\n", Dim(w, result.Meta.PackageNote))
	} else if result.Meta.ResolvedPackage != "" && result.Meta.FindingCount == 0 {
		fmt.Fprintf(w, "  %s\n", Dim(w, "No OSV advisories affect "+result.Meta.ResolvedPackage))
		if hint := scopedPackageHint(result.Meta.ResolvedPackage); hint != "" {
			fmt.Fprintf(w, "  %s\n", Dim(w, hint))
		}
	}
	if result.Meta.SuppressedCount > 0 {
		MetaLine(w, "Suppressed", fmt.Sprintf("%d ignored via .depfuseignore", result.Meta.SuppressedCount))
	}
	if result.Meta.AcceptedCount > 0 {
		MetaLine(w, "Decisions", fmt.Sprintf("%d accepted-risk (silent)", result.Meta.AcceptedCount))
	}
	if result.Meta.ReopenedCount > 0 {
		MetaLine(w, "Reopened", fmt.Sprintf("%d decisions need review", result.Meta.ReopenedCount))
	}
	renderCoverageBanner(w, result.Meta.Coverage)

	renderSummary(w, result.Summary)

	if result.Delta != nil && result.Delta.HasChanges() {
		renderDelta(w, result.Delta)
	}

	renderUpgradeRollup(w, result)

	if len(result.Accepted) > 0 {
		renderAcceptedRisk(w, result.Accepted)
	}

	if result.Meta.InputMode == models.InputModeCVE {
		renderCVEScan(w, result)
		fmt.Fprintln(w)
		return
	}

	actionItems := filterFindings(result.Findings, func(f models.Finding) bool {
		if f.Reopened {
			return true
		}
		return f.Verdict == models.VerdictFixNow || f.Verdict == models.VerdictFixSoon
	})
	if len(actionItems) > 0 {
		Section(w, "Action required", len(actionItems))
		renderFindingsTable(w, actionItems, result.Verbose)
		renderVerdictReceipts(w, actionItems)
		if result.Verbose {
			renderActionEvidenceTable(w, actionItems)
		}
		if hasWeaponized(actionItems) {
			fmt.Fprintf(w, "  %s\n", Dim(w, "Exploit signals describe the CVE, not proof it is reachable in your app (v0.1)."))
		}
		if result.Verbose {
			renderVerboseBriefings(w, actionItems)
		}
	}

	groups := []struct {
		title  string
		filter func(models.Finding) bool
	}{
		{"Production · direct", func(f models.Finding) bool {
			return f.Component.Scope == models.ScopeProd && f.Component.Direct &&
				f.Verdict != models.VerdictFixNow && f.Verdict != models.VerdictFixSoon
		}},
		{"Production · transitive", func(f models.Finding) bool {
			return f.Component.Scope == models.ScopeProd && !f.Component.Direct &&
				f.Verdict != models.VerdictFixNow && f.Verdict != models.VerdictFixSoon
		}},
		{"Development", func(f models.Finding) bool {
			return f.Component.Scope == models.ScopeDev &&
				f.Verdict != models.VerdictFixNow && f.Verdict != models.VerdictFixSoon
		}},
	}
	for _, g := range groups {
		items := filterFindings(result.Findings, g.filter)
		if len(items) == 0 {
			continue
		}
		if len(items) > 8 {
			renderShipCollapsed(w, g.title, items)
			continue
		}
		Section(w, g.title, len(items))
		renderFindingsTable(w, items, result.Verbose)
		if result.Verbose {
			renderFindingPackageContext(w, items)
		}
	}

	if result.ShowIgnored && len(result.Suppressed) > 0 {
		Section(w, "Suppressed", len(result.Suppressed))
		renderSuppressedTable(w, result.Suppressed)
	}

	renderAdvisorySection(w, result.Findings, result.Verbose)
	if result.Verbose {
		renderEcosystemContextSection(w, result.Findings)
	}

	fmt.Fprintln(w)
}

func renderCVEScan(w io.Writer, result models.ScanResult) {
	if len(result.Findings) == 0 {
		return
	}

	actionItems := filterFindings(result.Findings, func(f models.Finding) bool {
		return f.Verdict.IsAction()
	})
	if len(actionItems) > 0 {
		Section(w, "Action required", len(actionItems))
		renderCVELookupTable(w, actionItems)
		if result.Verbose {
			renderActionEvidenceTable(w, actionItems)
		}
		if hasWeaponized(actionItems) {
			fmt.Fprintf(w, "  %s\n", Dim(w, "Exploit signals describe the CVE, not proof it is reachable in your app (v0.1)."))
		}
	}

	other := filterFindings(result.Findings, func(f models.Finding) bool {
		return !f.Verdict.IsAction()
	})
	if len(other) > 0 {
		Section(w, "CVE lookup", len(other))
		renderCVELookupTable(w, other)
		fmt.Fprintf(w, "  %s\n", Dim(w, "Advisory-only lookup — not tied to an installed dependency version"))
	}

	if result.Verbose {
		entries := uniqueAdvisoryEntries(result.Findings)
		if len(entries) > 0 {
			fmt.Fprintln(w)
			Section(w, "Details", len(entries))
			renderAdvisoryDetails(w, entries)
		}
	} else if len(other) > 0 {
		fmt.Fprintf(w, "  %s\n", Dim(w, "use --verbose for full advisory details and reference links"))
	}
}

func renderCVELookupTable(w io.Writer, items []models.Finding) {
	var rows [][]string
	for _, f := range items {
		advisory, cve := VulnColumns(w, f.CveMatch)
		if cve == "" {
			cve = Dim(w, "—")
		}
		summary := truncateOneLine(f.CveMatch.Summary, 52)
		if summary == "" {
			summary = Dim(w, "—")
		}
		rows = append(rows, []string{
			TierStyle(w, f.Classification.Priority.String()),
			advisory,
			cve,
			fmt.Sprintf("%s@%s", f.Component.Name, f.Component.Version),
			summary,
			FormatSignals(w, f.Classification.Signals),
			formatFixFinding(w, f),
			VerdictStyle(w, string(f.Verdict)),
		})
	}
	fmt.Fprintln(w)
	Table{
		Headers: []string{"Level", "Advisory", "CVE", "Package", "Summary", "Signals", "Fix", "Action"},
		Align:   repeatAlign(8, AlignLeft),
		// Advisory/CVE/Verdict left uncapped so identifiers are never truncated;
		// Summary/Package/Signals absorb terminal-width pressure.
		MaxCol: []int{0, 0, 0, 24, 34, 24, 16, 0},
		Rows:   rows,
	}.Print(w)
	fmt.Fprintln(w)
}

type advisoryEntry struct {
	match models.CveMatch
	tier  models.Priority
}

func renderAdvisorySection(w io.Writer, findings []models.Finding, verbose bool) {
	entries := uniqueAdvisoryEntries(findings)
	if len(entries) == 0 {
		return
	}
	// Findings table already lists each advisory for multi-CVE scans; details live in --verbose.
	if !verbose && len(findings) >= len(entries) && len(entries) > 1 {
		return
	}

	Section(w, "Advisories", len(entries))
	if verbose {
		renderAdvisoryDetails(w, entries)
		return
	}
	renderAdvisoryIndexTable(w, entries)
	fmt.Fprintf(w, "  %s\n\n", Dim(w, "use --verbose for details and reference links"))
}

func renderAdvisoryIndexTable(w io.Writer, entries []advisoryEntry) {
	var rows [][]string
	for _, e := range entries {
		advisory := firstNonEmpty(e.match.GHSAID, e.match.OSVID, e.match.CVEID)
		cve := canonicalCVE(e.match)
		if cve == "" {
			cve = Dim(w, "—")
		}
		summary := truncateOneLine(e.match.Summary, 56)
		if summary == "" {
			summary = Dim(w, "—")
		}
		rows = append(rows, []string{
			TierStyle(w, e.tier.String()),
			advisory,
			cve,
			summary,
			formatFix(w, e.match),
			primaryAdvisoryURL(e.match),
		})
	}
	Table{
		Headers: []string{"Level", "Advisory", "CVE", "Summary", "Fix", "Link"},
		Align:   []Align{AlignLeft, AlignLeft, AlignLeft, AlignLeft, AlignLeft, AlignLeft},
		MaxCol:  []int{0, 24, 18, 56, 10, 0},
		Rows:    rows,
	}.Print(w)
	fmt.Fprintln(w)
}

func renderAdvisoryDetails(w io.Writer, entries []advisoryEntry) {
	for _, e := range entries {
		cm := e.match
		label := firstNonEmpty(cm.GHSAID, cm.OSVID, cm.CVEID)
		fmt.Fprintf(w, "  %s\n", Bold(w, label))
		if cve := canonicalCVE(cm); cve != "" && cve != label {
			MetaLine(w, "CVE", cve)
		}
		if cm.Summary != "" {
			MetaLine(w, "Summary", cm.Summary)
		}
		if cm.Details != "" {
			MetaLine(w, "Details", cm.Details)
		}
		if cm.Severity != "" {
			MetaLine(w, "Severity", formatAdvisorySeverity(cm.Severity))
		}
		if !cm.Published.IsZero() {
			MetaLine(w, "Published", cm.Published.UTC().Format("2006-01-02"))
		}
		if cm.OSVID != "" {
			MetaLine(w, "OSV", "https://osv.dev/vulnerabilities/"+cm.OSVID)
		}
		rows := referenceRows(cm.References)
		if len(rows) > 0 {
			fmt.Fprintln(w)
			Table{
				Headers: []string{"Source", "URL"},
				Align:   []Align{AlignLeft, AlignLeft},
				MaxCol:  []int{16, 0},
				Rows:    rows,
			}.Print(w)
		}
		fmt.Fprintln(w)
	}
}

func uniqueAdvisoryEntries(findings []models.Finding) []advisoryEntry {
	byID := map[string]advisoryEntry{}
	for _, f := range findings {
		id := f.CveMatch.AdvisoryID()
		if id == "" {
			continue
		}
		if _, ok := byID[id]; !ok {
			byID[id] = advisoryEntry{match: f.CveMatch, tier: f.Classification.Priority}
		}
	}
	if len(byID) == 0 {
		return nil
	}
	out := make([]advisoryEntry, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].tier != out[j].tier {
			return out[i].tier < out[j].tier
		}
		return out[i].match.AdvisoryID() < out[j].match.AdvisoryID()
	})
	return out
}

func primaryAdvisoryURL(cm models.CveMatch) string {
	for _, ref := range cm.References {
		if strings.Contains(ref, "/security/advisories/") {
			return ref
		}
	}
	if cm.OSVID != "" {
		return "https://osv.dev/vulnerabilities/" + cm.OSVID
	}
	if len(cm.References) > 0 {
		return cm.References[0]
	}
	return ""
}

func truncateOneLine(text string, max int) string {
	text = strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if max <= 0 || len(text) <= max {
		return text
	}
	if max <= 3 {
		return text[:max]
	}
	return text[:max-1] + "…"
}

func renderSuppressedTable(w io.Writer, items []models.Finding) {
	var rows [][]string
	for _, f := range items {
		advisory, cve := VulnColumns(w, f.CveMatch)
		if cve == "" {
			cve = Dim(w, "—")
		}
		rows = append(rows, []string{
			TierStyle(w, f.Classification.Priority.String()),
			advisory,
			cve,
			fmt.Sprintf("%s@%s", f.Component.Name, f.Component.Version),
			Dim(w, f.SuppressionReason),
		})
	}
	Table{
		Headers: []string{"Level", "Advisory", "CVE", "Package", "Reason"},
		Align:   []Align{AlignLeft, AlignLeft, AlignLeft, AlignLeft, AlignLeft},
		MaxCol:  []int{0, 28, 18, 20, 40},
		Rows:    rows,
	}.Print(w)
}

func renderSummary(w io.Writer, s models.ScanSummary) {
	Section(w, "Summary", 0)

	total := s.Total
	if total == 0 {
		total = 1
	}
	exploitablePct := float64(s.Exploitable()) / float64(total)
	fixNowPct := float64(s.FixNow) / float64(total)
	okPct := float64(s.OK) / float64(total)

	Table{
		Headers: []string{"Exploitable", "Fix Now", "Fix Soon", "OK", "Backlog"},
		Align:   []Align{AlignRight, AlignRight, AlignRight, AlignRight, AlignRight},
		Rows: [][]string{{
			Bold(w, fmt.Sprintf("%d", s.Exploitable())),
			Bold(w, fmt.Sprintf("%d", s.FixNow)),
			fmt.Sprintf("%d", s.FixSoon),
			fmt.Sprintf("%d", s.OK),
			fmt.Sprintf("%d", s.Backlog()),
		}},
	}.Print(w)

	if s.Total > 0 {
		MetaLine(w, "Levels", fmt.Sprintf("P0=%d · P1=%d · P2=%d · P3=%d · P4=%d",
			s.P0, s.P1, s.P2, s.P3, s.P4))
	}

	renderRatioBar(w, "Exploitable", exploitablePct, s.Exploitable(), total, orange)
	renderRatioBar(w, "Fix Now", fixNowPct, s.FixNow, total, red)
	renderRatioBar(w, "OK", okPct, s.OK, total, green)

	if s.Total > 0 && s.Exploitable() == 0 && s.FixSoon == 0 && s.FixNow == 0 {
		fmt.Fprintf(w, "  %s\n", Dim(w, "No known exploit (P0/P1/P2) — release may proceed; review remaining advisories."))
	}
}

func renderRatioBar(w io.Writer, label string, ratio float64, count, total int, color string) {
	bar := ProgressBar(24, ratio, "█", "░")
	if !Color(w) {
		bar = ProgressBar(24, ratio, "#", "-")
	} else {
		bar = color + bar + reset
	}
	label = label + strings.Repeat(" ", max(0, 12-runewidth.StringWidth(label)))
	if Color(w) {
		fmt.Fprintf(w, "  %s%s%s %s (%d/%d)\n", dim, label, reset, bar, count, total)
		return
	}
	fmt.Fprintf(w, "  %s %s (%d/%d)\n", label, bar, count, total)
}

func renderFindingsTable(w io.Writer, items []models.Finding, verbose bool) {
	_ = verbose
	var rows [][]string
	for _, f := range items {
		advisory, cve := VulnColumns(w, f.CveMatch)
		if cve == "" {
			cve = Dim(w, "—")
		}
		row := []string{
			TierStyle(w, f.Classification.Priority.String()),
			advisory,
			cve,
			fmt.Sprintf("%s@%s", f.Component.Name, f.Component.Version),
			formatPath(w, f.Component),
			FormatSignals(w, f.Classification.Signals),
			formatFixFinding(w, f),
			VerdictStyle(w, string(f.Verdict)),
		}
		rows = append(rows, row)
	}
	headers := []string{"Level", "Advisory", "CVE", "Package", "Path", "Signals", "Fix", "Action"}
	Table{
		Headers: headers,
		Align:   repeatAlign(len(headers), AlignLeft),
		MaxCol:  findingsMaxCol(true),
		Rows:    rows,
	}.Print(w)
}

func uniqueAdvisories(findings []models.Finding) []models.CveMatch {
	entries := uniqueAdvisoryEntries(findings)
	out := make([]models.CveMatch, len(entries))
	for i, e := range entries {
		out[i] = e.match
	}
	return out
}

func referenceRows(refs []string) [][]string {
	seen := map[string]bool{}
	var rows [][]string
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		rows = append(rows, []string{referenceLabel(ref), ref})
	}
	return rows
}

func referenceLabel(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "Reference"
	}
	host := strings.ToLower(u.Host)
	path := strings.ToLower(u.Path)
	switch {
	case strings.Contains(host, "nvd.nist.gov"):
		return "NVD"
	case strings.Contains(host, "github.com") && strings.Contains(path, "/advisories/"):
		return "GitHub Advisory"
	case strings.Contains(host, "github.com") && strings.Contains(path, "/issues/"):
		return "GitHub Issue"
	case strings.Contains(host, "github.com") && strings.Contains(path, "/pull/"):
		return "GitHub PR"
	case strings.Contains(host, "github.com"):
		return "GitHub"
	case strings.Contains(host, "gitlab."):
		return "GitLab"
	case strings.Contains(host, "osv.dev"):
		return "OSV"
	default:
		return u.Host
	}
}

func formatAdvisorySeverity(severity string) string {
	severity = strings.TrimSpace(severity)
	if severity == "" {
		return ""
	}
	if strings.HasPrefix(severity, "CVSS:") {
		return severity
	}
	return severity
}

func scopedPackageHint(resolved string) string {
	at := strings.LastIndex(resolved, "@")
	if at <= 0 {
		return ""
	}
	name := resolved[:at]
	if strings.HasPrefix(name, "@") || !strings.Contains(name, "/") {
		return ""
	}
	return fmt.Sprintf("Did you mean @%s? Scoped npm packages require the @ prefix.", name)
}

func truncateAdvisoryText(text string, verbose bool) string {
	text = strings.Join(strings.Fields(text), " ")
	if verbose || len(text) <= 240 {
		return text
	}
	return text[:237] + "..."
}

func renderActionEvidenceTable(w io.Writer, items []models.Finding) {
	rows := actionEvidenceRows(w, items)
	if len(rows) == 0 {
		return
	}
	fmt.Fprintln(w)
	Table{
		Headers: []string{"CVE", "Source", "Evidence", "URL"},
		Align:   []Align{AlignLeft, AlignLeft, AlignLeft, AlignLeft},
		MaxCol:  []int{18, 8, 36, 0},
		Rows:    rows,
	}.Print(w)
	fmt.Fprintln(w)
}

func renderVerdictReceipts(w io.Writer, items []models.Finding) {
	for _, f := range items {
		if !f.Verdict.IsAction() || len(f.Receipts) == 0 {
			continue
		}
		cve := canonicalCVE(f.CveMatch)
		if cve == "" {
			cve = firstNonEmpty(f.CveMatch.CVEID, f.CveMatch.OSVID)
		}
		header := fmt.Sprintf("%s because:", f.Verdict)
		if cve != "" {
			header = fmt.Sprintf("%s (%s) because:", f.Verdict, cve)
		}
		fmt.Fprintf(w, "  %s\n", Bold(w, header))
		for _, r := range f.Receipts {
			tag := receiptTag(w, r.Kind)
			line := r.Claim
			if r.URL != "" {
				line = fmt.Sprintf("%s — %s", line, Dim(w, r.URL))
			}
			fmt.Fprintf(w, "    • %s %s\n", tag, line)
		}
		fmt.Fprintln(w)
	}
}

func receiptTag(w io.Writer, kind models.ReceiptKind) string {
	switch kind {
	case models.ReceiptKEV:
		return badge(w, "KEV", red)
	case models.ReceiptNuclei:
		return badge(w, "Nuc", orange)
	case models.ReceiptMSF:
		return badge(w, "MSF", yellow)
	case models.ReceiptEDB:
		return badge(w, "EDB", yellow)
	case models.ReceiptPoC:
		return badge(w, "PoC", cyan)
	case models.ReceiptEPSS:
		return badge(w, "EPSS", green)
	case models.ReceiptEcosystem:
		return badge(w, "Eco", cyan)
	case models.ReceiptExposure:
		return badge(w, "Exp", cyan)
	default:
		return fmt.Sprintf("[%s]", kind)
	}
}

func renderDelta(w io.Writer, d *models.ScanDelta) {
	if d == nil || !d.HasChanges() {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", Bold(w, "Changes since "+d.PreviousScanAt.UTC().Format("2006-01-02T15:04:05Z")))
	renderDeltaBucket(w, "ESCALATED", d.Escalated)
	renderDeltaBucket(w, "DE-ESCALATED", d.Deescalated)
	renderDeltaBucket(w, "EPSS SHIFTS", d.EPSSShifts)
	renderDeltaBucket(w, "NEW", d.NewFindings)
	renderDeltaBucket(w, "REMOVED", d.Removed)
	fmt.Fprintln(w)
}

func renderDeltaBucket(w io.Writer, title string, items []models.FindingDelta) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s (%d)\n", Bold(w, title), len(items))
	for _, item := range items {
		cve := item.CVEID
		if cve == "" {
			cve = item.Key
		}
		fmt.Fprintf(w, "    %s  %s  %s\n", cve, item.Summary, Dim(w, item.Package))
	}
}

func renderUpgradeRollup(w io.Writer, result models.ScanResult) {
	all := append(append([]models.Finding{}, result.Findings...), result.Accepted...)
	rollups := rollup.BuildUpgradeRollup(result.Components, all)
	if len(rollups) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", Bold(w, "Priority upgrades"))
	fmt.Fprintf(w, "  %s\n", Dim(w, "Upgrade declared deps to clear the most CVE matches"))
	for _, r := range rollups {
		root := r.RootName
		if r.RootVersion != "" {
			root += "@" + r.RootVersion
		}
		fix := "see advisory"
		if r.FixVersion != "" {
			fix = "≥ " + r.FixVersion
		}
		fmt.Fprintf(w, "    %s  %s  %d CVE · %d pkg  →  %s\n",
			formatLevel(w, r.Worst), root, r.FindingCount, r.PackageCount, fix)
	}
	fmt.Fprintln(w)
}

func renderCoverageBanner(w io.Writer, cov *models.ScanCoverageMeta) {
	if cov == nil || cov.Status == "complete" {
		return
	}
	fmt.Fprintln(w)
	if cov.IsIncomplete() {
		fmt.Fprintf(w, "  %s\n", Danger(w, cov.Message))
		fmt.Fprintf(w, "  %s\n", Dim(w, "Exit code 1 — commit a lockfile for full transitive coverage."))
	} else {
		fmt.Fprintf(w, "  %s\n", Dim(w, cov.Message))
	}
	fmt.Fprintln(w)
}

func renderAcceptedRisk(w io.Writer, accepted []models.Finding) {
	if len(accepted) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s (%d)\n", Bold(w, "Accepted risk (silent)"), len(accepted))
	fmt.Fprintf(w, "  %s\n", Dim(w, "Reopens when: "+strings.Join(models.ReopenPolicyLabels(), ", ")))
	for _, f := range accepted {
		cve := firstNonEmpty(f.CveMatch.CVEID, f.CveMatch.GHSAID)
		reason := strings.TrimSpace(f.DecisionReason)
		if reason == "" {
			reason = "accepted-risk"
		}
		fmt.Fprintf(w, "    %s  %s@%s  — %s\n", cve, f.Component.Name, f.Component.Version, Dim(w, reason))
	}
	fmt.Fprintln(w)
}

func actionEvidenceRows(w io.Writer, items []models.Finding) [][]string {
	var rows [][]string
	for _, f := range items {
		cve := canonicalCVE(f.CveMatch)
		if cve == "" {
			cve = firstNonEmpty(f.CveMatch.CVEID, f.CveMatch.OSVID, f.CveMatch.GHSAID)
		}
		if cve == "" {
			cve = Dim(w, "—")
		}
		added := false
		for _, e := range f.Classification.Evidence {
			if e.Claim == "" && e.URL == "" {
				continue
			}
			claim := e.Claim
			if claim == "" {
				claim = Dim(w, "—")
			}
			url := e.URL
			if url == "" {
				url = Dim(w, "—")
			}
			rows = append(rows, []string{
				cve,
				sourceLabel(w, e.Source),
				claim,
				url,
			})
			added = true
		}
		if !added {
			claim := f.VerdictReason
			if claim == "" {
				claim = f.CveMatch.Summary
			}
			if claim == "" {
				continue
			}
			rows = append(rows, []string{
				cve,
				Dim(w, "—"),
				claim,
				Dim(w, "—"),
			})
		}
	}
	return rows
}

func sourceLabel(w io.Writer, s models.Source) string {
	switch s {
	case models.SourceKEV:
		return badge(w, "KEV", red)
	case models.SourceVulnCheckXDB:
		return badge(w, "XDB", orange)
	case models.SourceNuclei:
		return badge(w, "Nuc", orange)
	case models.SourceMetasploit:
		return badge(w, "MSF", yellow)
	case models.SourceExploitDB:
		return badge(w, "EDB", yellow)
	case models.SourcePoCGitHub:
		return badge(w, "PoC", cyan)
	case models.SourceEPSS:
		return badge(w, "EPSS", green)
	case models.SourceOSV:
		return badge(w, "OSV", cyan)
	default:
		if s == "" {
			return Dim(w, "—")
		}
		return string(s)
	}
}

func formatCitation(e models.Citation) string {
	if e.URL == "" {
		return e.Claim
	}
	return fmt.Sprintf("%s — %s", e.Claim, e.URL)
}

func renderVerboseBriefings(w io.Writer, items []models.Finding) {
	for _, f := range items {
		fmt.Fprintf(w, "  %s %s\n", Bold(w, f.CveMatch.CVEID+":"), Dim(w, f.ExposureNote))
		if f.PackageContext != nil {
			renderPackageContextLine(w, f.Component, f.PackageContext, "    ")
		}
		for _, line := range compactBriefingLines(f) {
			fmt.Fprintf(w, "    • %s\n", line)
		}
		if f.Remediation != nil {
			fmt.Fprintf(w, "    → %s\n", remediationLine(w, *f.Remediation, f.Component.Name))
		}
	}
	fmt.Fprintln(w)
}

// remediationLine renders the verbose upgrade directive, flagging a breaking
// (major) bump in orange and a genuinely unfixable finding in red.
func remediationLine(w io.Writer, r models.Remediation, pkg string) string {
	line := r.UpgradeLine(pkg)
	if !Color(w) {
		return line
	}
	switch {
	case !r.FixAvailable:
		return red + line + reset
	case r.Breaking:
		return orange + line + reset
	default:
		return green + line + reset
	}
}

func compactBriefingLines(f models.Finding) []string {
	var lines []string
	if f.VerdictReason != "" {
		lines = append(lines, f.VerdictReason)
	}
	for _, e := range f.Classification.Evidence {
		if e.Claim != "" {
			lines = append(lines, formatCitation(e))
			if len(lines) >= 3 {
				break
			}
		}
	}
	if len(lines) == 0 && f.CveMatch.Summary != "" {
		lines = append(lines, f.CveMatch.Summary)
	}
	return lines
}

func formatPath(w io.Writer, c models.Component) string {
	chain := resolve.FormatDependencyPath(c)
	if chain == "" {
		return Dim(w, "—")
	}
	return chain
}

func repeatAlign(n int, a Align) []Align {
	out := make([]Align, n)
	for i := range out {
		out[i] = a
	}
	return out
}

func findingsMaxCol(showPath bool) []int {
	// Tier, Advisory, CVE, Package[, Path], Signals, Fix, Verdict.
	// Advisory/CVE/Verdict uncapped so identifiers stay whole; Package/Path/
	// Signals absorb terminal-width pressure.
	if showPath {
		return []int{0, 0, 0, 24, 28, 24, 16, 0}
	}
	return []int{0, 0, 0, 28, 24, 16, 0}
}

// hasWeaponized reports whether any finding carries an Exploited/Exploit-Ready level.
func hasWeaponized(items []models.Finding) bool {
	for _, f := range items {
		if f.Classification.Priority <= models.PriorityP1 {
			return true
		}
	}
	return false
}

func formatFix(w io.Writer, c models.CveMatch) string {
	if len(c.FixedVersions) == 0 {
		return Dim(w, "—")
	}
	fix := c.FixedVersions[0]
	if len(c.FixedVersions) > 1 {
		fix += "+"
	}
	return fix
}

// formatFixFinding renders the minimal safe upgrade with its blast radius: the
// smallest published version that clears the vuln, tagged patch/minor/major so a
// breaking bump is visible at a glance and "no fix yet" surfaces stuck findings.
func formatFixFinding(w io.Writer, f models.Finding) string {
	r := f.Remediation
	if r == nil {
		return formatFix(w, f.CveMatch)
	}
	if !r.FixAvailable {
		return Dim(w, r.Label())
	}
	switch r.Jump {
	case models.JumpMajor:
		if Color(w) {
			return r.FixVersion + " " + orange + "(major)" + reset
		}
		return r.FixVersion + " (major)"
	case models.JumpPatch:
		if Color(w) {
			return r.FixVersion + " " + green + "(patch)" + reset
		}
		return r.FixVersion + " (patch)"
	case models.JumpMinor:
		return r.FixVersion + " " + Dim(w, "(minor)")
	default:
		return r.FixVersion
	}
}

func filterFindings(in []models.Finding, fn func(models.Finding) bool) []models.Finding {
	var out []models.Finding
	for _, f := range in {
		if fn(f) {
			out = append(out, f)
		}
	}
	return out
}

func renderShipCollapsed(w io.Writer, title string, items []models.Finding) {
	Section(w, title, len(items))
	renderFindingsTable(w, items, false)
	fmt.Fprintf(w, "  %s\n", Dim(w, "use --verbose for dependency paths and briefings"))
	fmt.Fprintln(w)
}

// FeedRow is one feed for status display.
type FeedRow struct {
	Name, LastSuccess, LastError string
	Artifacts                    int
}

// RenderCollectDone prints post-collect summary.
func RenderCollectDone(w io.Writer, path, version string, total int, feeds []FeedRow) {
	fmt.Fprintln(w)
	MetaLine(w, "Database", path)
	MetaLine(w, "Version", version)
	MetaLine(w, "Artifacts", fmt.Sprintf("%d", total))

	Section(w, "Feeds", len(feeds))
	var rows [][]string
	for _, f := range feeds {
		rows = append(rows, []string{f.Name, f.LastSuccess, fmt.Sprintf("%d", f.Artifacts)})
	}
	Table{
		Headers: []string{"Feed", "Last success", "Artifacts"},
		Align:   []Align{AlignLeft, AlignLeft, AlignRight},
		Rows:    rows,
	}.Print(w)
	fmt.Fprintln(w)
}
