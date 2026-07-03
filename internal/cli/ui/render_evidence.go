package ui

import (
	"fmt"
	"io"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// RenderEvidenceTimeline prints Milestone 1 timeline output for cve --timeline.
func RenderEvidenceTimeline(w io.Writer, tl *models.EvidenceTimeline) {
	if tl == nil {
		return
	}
	fmt.Fprintf(w, "\n  Evidence timeline  %s\n\n", Bold(w, tl.CVE))
	fmt.Fprintf(w, "  Level            %s\n", formatLevel(w, tl.State.Level))
	fmt.Fprintf(w, "  Evidence hash    %s\n", Dim(w, tl.State.Hash))
	if !tl.State.ChangedAt.IsZero() {
		fmt.Fprintf(w, "  Last changed     %s\n", tl.State.ChangedAt.UTC().Format("2006-01-02"))
	}
	fmt.Fprintf(w, "  Signals          %s\n\n", FormatSignals(w, tl.State.Signals))

	if tl.DecisionImpact != nil && tl.DecisionImpact.Summary != "" {
		label := "Decision impact"
		if tl.DecisionImpact.ReopenRequired {
			label = Bold(w, "Decision impact") + "  " + badge(w, "REOPEN", red)
		}
		fmt.Fprintf(w, "  %s\n", label)
		if !tl.DecisionImpact.PreviousScanAt.IsZero() {
			fmt.Fprintf(w, "    Previous scan  %s\n", tl.DecisionImpact.PreviousScanAt.UTC().Format("2006-01-02"))
		}
		if tl.DecisionImpact.PreviousLevel.String() != "Unknown" {
			fmt.Fprintf(w, "    Previous level %s\n", tl.DecisionImpact.PreviousLevel)
		}
		fmt.Fprintf(w, "    %s\n\n", tl.DecisionImpact.Summary)
	}

	if len(tl.State.Events) == 0 {
		fmt.Fprintf(w, "  No dated exploit-evidence artifacts indexed.\n\n")
		return
	}

	fmt.Fprintf(w, "  Timeline\n")
	for _, ev := range tl.State.Events {
		when := "unknown"
		if !ev.At.IsZero() {
			when = ev.At.UTC().Format("2006-01-02")
		}
		line := fmt.Sprintf("    %s  [%s]  %s", when, ev.Source, ev.Summary)
		if ev.URL != "" {
			line += "  " + Dim(w, ev.URL)
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
}

// RenderEvidenceDiff prints evidence diff output.
func RenderEvidenceDiff(w io.Writer, diff *models.EvidenceDiff) {
	if diff == nil {
		return
	}
	title := fmt.Sprintf("Evidence diff  %s → %s", diff.BaselineLabel, diff.CurrentLabel)
	if !diff.Since.IsZero() {
		title = fmt.Sprintf("Evidence diff since %s", diff.Since.Format("2006-01-02"))
	}
	fmt.Fprintf(w, "\n  %s\n\n", Bold(w, title))

	if len(diff.Changes) == 0 {
		fmt.Fprintf(w, "  No exploit-evidence changes detected.\n\n")
		return
	}

	tbl := Table{Headers: []string{"CVE", "Kind", "Level", "Summary"}}
	for _, ch := range diff.Changes {
		level := formatLevelChange(ch.PrevLevel, ch.CurrLevel)
		tbl.Rows = append(tbl.Rows, []string{ch.CVE, string(ch.Kind), level, ch.Summary})
	}
	tbl.Print(w)
	fmt.Fprintln(w)
}

// RenderPackageEvidence prints evidence-focused package lookup output.
func RenderPackageEvidence(w io.Writer, pkg string, rows []models.PackageEvidenceRow) {
	fmt.Fprintf(w, "\n  Package evidence  %s\n\n", Bold(w, pkg))
	if len(rows) == 0 {
		fmt.Fprintf(w, "  No CVE matches with exploit evidence.\n\n")
		return
	}
	for _, row := range rows {
		fmt.Fprintf(w, "  %s  %s  %s\n", row.CVE, formatLevel(w, row.Level), row.Verdict)
		fmt.Fprintf(w, "    hash     %s\n", Dim(w, row.EvidenceHash))
		fmt.Fprintf(w, "    signals  %s\n", FormatSignals(w, row.Signals))
		if len(row.Events) > 0 {
			fmt.Fprintf(w, "    events   %d indexed artifact(s)\n", len(row.Events))
			for _, ev := range row.Events {
				when := ev.At.UTC().Format("2006-01-02")
				if ev.At.IsZero() {
					when = "unknown"
				}
				fmt.Fprintf(w, "      %s  [%s]  %s\n", when, ev.Source, ev.Summary)
			}
		}
		fmt.Fprintln(w)
	}
}

func formatLevel(w io.Writer, t models.Priority) string {
	switch t {
	case models.PriorityP0:
		return badge(w, t.String(), red)
	case models.PriorityP1:
		return badge(w, t.String(), orange)
	case models.PriorityP2:
		return badge(w, t.String(), yellow)
	case models.PriorityP3:
		return badge(w, t.String(), cyan)
	default:
		return Dim(w, t.String())
	}
}

func formatLevelChange(prev, curr models.Priority) string {
	if prev != 0 && curr != 0 && prev != curr {
		return fmt.Sprintf("%s → %s", prev, curr)
	}
	if curr != 0 {
		return curr.String()
	}
	if prev != 0 {
		return prev.String()
	}
	return "—"
}
