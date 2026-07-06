package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/verdict"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

var frameworkPackages = map[string]string{
	"express": "express", "next": "next.js", "@nestjs/core": "nestjs",
	"react": "react", "koa": "koa", "fastify": "fastify",
}

// Rank sorts findings by tier, confidence, freshness, prod/direct priority.
func Rank(findings []models.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Classification.Priority != b.Classification.Priority {
			return a.Classification.Priority < b.Classification.Priority
		}
		if a.Classification.Confidence != b.Classification.Confidence {
			return a.Classification.Confidence > b.Classification.Confidence
		}
		if !a.Classification.Freshness.Equal(b.Classification.Freshness) {
			return a.Classification.Freshness.After(b.Classification.Freshness)
		}
		priorityA := scopePriority(a.Component)
		priorityB := scopePriority(b.Component)
		if priorityA != priorityB {
			return priorityA < priorityB
		}
		return a.CveMatch.CVEID < b.CveMatch.CVEID
	})
}

func scopePriority(c models.Component) int {
	if c.Scope == models.ScopeProd && c.Direct {
		return 0
	}
	if c.Scope == models.ScopeProd {
		return 1
	}
	if c.Direct {
		return 2
	}
	return 3
}

// ExposureNote returns a coarse, non-reachability exposure label.
func ExposureNote(comp models.Component) string {
	scope := "production"
	if comp.Scope == models.ScopeDev {
		scope = "development"
	}
	direct := "transitive"
	if comp.Direct {
		direct = "direct"
	}
	note := fmt.Sprintf("%s dependency, %s (not a reachability assessment)", scope, direct)
	if fw, ok := frameworkPackages[strings.ToLower(comp.Name)]; ok {
		note += fmt.Sprintf("; framework-adjacent: %s", fw)
	}
	return note
}

// Summarize computes scan summary counts.
func Summarize(findings []models.Finding) models.ScanSummary {
	s := models.ScanSummary{Total: len(findings)}
	for _, f := range findings {
		switch f.Classification.Priority {
		case models.PriorityP0:
			s.P0++
		case models.PriorityP1:
			s.P1++
		case models.PriorityP2:
			s.P2++
		case models.PriorityP3:
			s.P3++
		case models.PriorityP4:
			s.P4++
		}
		switch f.Verdict {
		case models.VerdictFixNow, models.VerdictPatchNow:
			s.FixNow++
		case models.VerdictFixSoon, models.VerdictPatchSoon:
			s.FixSoon++
		case models.VerdictOK, models.VerdictWatch:
			s.OK++
		}
	}
	return s
}

// RenderCLI prints rich terminal output (legacy writer; use cli/ui.RenderScan for TTY).
func RenderCLI(w ioWriter, result models.ScanResult) {
	renderCLILegacy(w, result)
}

func renderCLILegacy(w ioWriter, result models.ScanResult) {
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, " Snapshot: %s (%s)\n", result.Meta.SnapshotVersion, result.Meta.SnapshotHash)
	fmt.Fprintf(w, " Components: %d | Findings: %d | %dms\n\n",
		result.Meta.ComponentCount, result.Meta.FindingCount, result.Meta.DurationMS)
	fmt.Fprintf(w, " Summary: %d weaponized exposure (P0/P1), %d backlog (P3/P4)\n",
		result.Summary.WeaponizedExposure(), result.Summary.Backlog())
	fmt.Fprintf(w, " Actions: FIX NOW=%d  FIX SOON=%d  OK=%d\n\n",
		result.Summary.FixNow, result.Summary.FixSoon, result.Summary.OK)

	groups := []struct {
		title  string
		filter func(models.Finding) bool
	}{
		{"PRODUCTION — DIRECT", func(f models.Finding) bool { return f.Component.Scope == models.ScopeProd && f.Component.Direct }},
		{"PRODUCTION — TRANSITIVE", func(f models.Finding) bool { return f.Component.Scope == models.ScopeProd && !f.Component.Direct }},
		{"DEVELOPMENT", func(f models.Finding) bool { return f.Component.Scope == models.ScopeDev }},
	}
	for _, g := range groups {
		var items []models.Finding
		for _, f := range result.Findings {
			if g.filter(f) {
				items = append(items, f)
			}
		}
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(w, "── %s ──\n", g.title)
		for _, f := range items {
			fmt.Fprintf(w, " [%s] %s  %s@%s  →  %s\n",
				f.Classification.Priority, f.CveMatch.CVEID, f.Component.Name, f.Component.Version, f.Verdict)
		}
		fmt.Fprintln(w)
	}
}

type ioWriter interface {
	Write([]byte) (int, error)
}

// RenderMarkdown writes report.md case-file format.
func RenderMarkdown(path string, result models.ScanResult) error {
	var b strings.Builder
	b.WriteString("# Depfuse Report\n\n")
	b.WriteString(fmt.Sprintf("- **Scanned:** %s\n", result.Meta.Timestamp.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- **Input:** %s\n", result.Meta.InputPath))
	b.WriteString(fmt.Sprintf("- **Snapshot:** %s (`%s`)\n", result.Meta.SnapshotVersion, result.Meta.SnapshotHash))
	b.WriteString(fmt.Sprintf("- **Summary:** %d weaponized exposure, %d backlog\n\n", result.Summary.WeaponizedExposure(), result.Summary.Backlog()))

	for _, f := range result.Findings {
		if f.Classification.Priority > models.PriorityP2 {
			continue
		}
		b.WriteString(fmt.Sprintf("---\n\n## %s — %s\n\n", f.CveMatch.CVEID, f.Classification.Priority))
		b.WriteString(fmt.Sprintf("**Package:** `%s@%s`  \n**Verdict:** %s  \n**Exposure:** %s\n\n",
			f.Component.Name, f.Component.Version, f.Verdict, f.ExposureNote))
		if f.Remediation != nil {
			b.WriteString(fmt.Sprintf("**Fix:** %s\n\n", f.Remediation.UpgradeLine(f.Component.Name)))
		}
		b.WriteString(f.Briefing + "\n")
	}

	seen := map[string]bool{}
	for _, f := range result.Findings {
		id := f.CveMatch.AdvisoryID()
		if id == "" || seen[id] || (f.CveMatch.Summary == "" && len(f.CveMatch.References) == 0) {
			continue
		}
		seen[id] = true
		cm := f.CveMatch
		b.WriteString("---\n\n## Advisory — " + id + "\n\n")
		if cm.Summary != "" {
			b.WriteString("**Summary:** " + cm.Summary + "\n\n")
		}
		if cm.Details != "" {
			b.WriteString("**Details:** " + cm.Details + "\n\n")
		}
		if cm.Severity != "" {
			b.WriteString("**Severity:** " + cm.Severity + "\n\n")
		}
		if cm.OSVID != "" {
			b.WriteString(fmt.Sprintf("**OSV:** https://osv.dev/vulnerability/%s\n\n", cm.OSVID))
		}
		if len(cm.References) > 0 {
			b.WriteString("**References:**\n")
			for _, ref := range cm.References {
				b.WriteString("- " + ref + "\n")
			}
			b.WriteString("\n")
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// WriteOutputs writes all requested report formats to outDir (project scan filenames).
func WriteOutputs(outDir string, formats []string, result models.ScanResult) error {
	return WriteOutputsAt(OutputPathsFor(outDir, result, ""), formats, result)
}

// CIFailures returns findings that should fail CI.
func CIFailures(findings []models.Finding, failTiers map[models.Priority]bool) []models.Finding {
	var out []models.Finding
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		if verdict.ShouldFailCI(f.Component, f.Classification.Priority, failTiers) {
			out = append(out, f)
		}
	}
	return out
}

// EmitGitHubSuppressionWarnings prints workflow warnings for suppressed findings.
func EmitGitHubSuppressionWarnings(w ioWriter, suppressed []models.Finding) {
	for _, f := range suppressed {
		fmt.Fprintf(w, "::warning title=Depfuse suppressed::%s in %s@%s (%s)\n",
			f.CveMatch.CVEID, f.Component.Name, f.Component.Version, f.SuppressionReason)
	}
}

// EmitGitHubAnnotations prints workflow annotations for failures.
func EmitGitHubAnnotations(w ioWriter, failures []models.Finding) {
	for _, f := range failures {
		fmt.Fprintf(w, "::error title=Depfuse %s::%s in prod dependency %s@%s (%s)\n",
			f.Classification.Priority, f.CveMatch.CVEID, f.Component.Name, f.Component.Version, f.Verdict)
	}
}
