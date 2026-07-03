package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// RenderWatch prints the unified decision-memory watch report.
func RenderWatch(w io.Writer, wr models.WatchResult) {
	fmt.Fprintf(w, "\n  %s\n\n", Bold(w, "Watch — decision memory"))
	if wr.InputPath != "" {
		fmt.Fprintf(w, "  Input   %s\n", wr.InputPath)
	}
	if !wr.PreviousScanAt.IsZero() {
		fmt.Fprintf(w, "  Since   %s\n", wr.PreviousScanAt.UTC().Format("2006-01-02 15:04 UTC"))
	}
	fmt.Fprintln(w)

	if wr.Digest.Summary != "" {
		fmt.Fprintf(w, "  %s\n\n", Bold(w, wr.Digest.Summary))
	}

	if len(wr.Reopened) > 0 {
		fmt.Fprintf(w, "  %s (%d)\n", Bold(w, "Needs review"), len(wr.Reopened))
		for _, item := range wr.Reopened {
			fmt.Fprintf(w, "    %s  %s  %s\n", item.CVE, item.Package, formatLevel(w, item.Level))
			if item.ReopenSummary != "" {
				fmt.Fprintf(w, "      %s\n", item.ReopenSummary)
			}
			if item.Reason != "" {
				fmt.Fprintf(w, "      was: %s (%s)\n", item.Reason, item.Decision)
			}
		}
		fmt.Fprintln(w)
	}

	if len(wr.Escalated) > 0 {
		fmt.Fprintf(w, "  %s (%d)\n", Bold(w, "Escalated since last scan"), len(wr.Escalated))
		for _, d := range wr.Escalated {
			fmt.Fprintf(w, "    %s  %s  %s\n", d.CVEID, d.Package, d.Summary)
		}
		fmt.Fprintln(w)
	}

	if len(wr.EPSSShifts) > 0 {
		fmt.Fprintf(w, "  %s (%d)\n", Bold(w, "EPSS shifts since last scan"), len(wr.EPSSShifts))
		for _, d := range wr.EPSSShifts {
			fmt.Fprintf(w, "    %s  %s  %s\n", d.CVEID, d.Package, d.Summary)
		}
		fmt.Fprintln(w)
	}

	if len(wr.IntelChanges) > 0 {
		fmt.Fprintf(w, "  %s (%d)\n", Bold(w, "Intel evidence changes"), len(wr.IntelChanges))
		tbl := Table{Headers: []string{"CVE", "Kind", "Summary"}}
		for _, ch := range wr.IntelChanges {
			tbl.Rows = append(tbl.Rows, []string{ch.CVE, string(ch.Kind), ch.Summary})
		}
		tbl.Print(w)
		fmt.Fprintln(w)
	}

	if len(wr.Silent) > 0 {
		fmt.Fprintf(w, "  %s (%d)\n", Dim(w, "Silent (accepted decisions hold)"), len(wr.Silent))
		fmt.Fprintf(w, "  %s\n", Dim(w, "Reopens when: "+strings.Join(models.ReopenPolicyLabels(), ", ")))
		for _, item := range wr.Silent {
			fmt.Fprintf(w, "    %s  %s  %s", item.CVE, item.Package, Dim(w, string(item.Decision)))
			if item.Reason != "" {
				fmt.Fprintf(w, "  — %s", Dim(w, item.Reason))
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}

	if !wr.HasAttention() && len(wr.Silent) == 0 {
		fmt.Fprintf(w, "  Nothing needs attention. Run scan with decisions to build memory.\n\n")
	} else if !wr.HasAttention() {
		fmt.Fprintf(w, "  %s\n\n", Dim(w, "No reopens or escalations — accepted decisions hold."))
	}
}

// RenderDecideConfirm prints a decision record confirmation.
func RenderDecideConfirm(w io.Writer, d models.StoredDecision, path string) {
	fmt.Fprintf(w, "\n  Decision recorded\n\n")
	fmt.Fprintf(w, "  CVE              %s\n", d.CVE)
	if d.Package != "" {
		pkg := d.Package
		if d.Version != "" {
			pkg += "@" + d.Version
		}
		fmt.Fprintf(w, "  Scope            %s\n", pkg)
	}
	fmt.Fprintf(w, "  Decision         %s\n", d.Decision)
	fmt.Fprintf(w, "  Reason           %s\n", d.Reason)
	fmt.Fprintf(w, "  Level at decide  %s\n", d.DecidedWhenLevel)
	fmt.Fprintf(w, "  Evidence hash    %s\n", Dim(w, d.DecidedWhenEvidenceHash))
	fmt.Fprintf(w, "  Saved to         %s\n\n", path)
}

// RenderDecisionsList prints stored decisions as a table.
func RenderDecisionsList(w io.Writer, file []models.StoredDecision) {
	fmt.Fprintf(w, "\n  %s\n\n", Bold(w, "Stored decisions"))
	if len(file) == 0 {
		fmt.Fprintf(w, "  No decisions recorded. Use depfuse decide to accept or block a finding.\n\n")
		return
	}
	tbl := Table{Headers: []string{"CVE", "Package", "Decision", "Level", "Reason"}}
	for _, d := range file {
		pkg := d.Package
		if d.Version != "" {
			pkg += "@" + d.Version
		}
		if pkg == "" {
			pkg = "—"
		}
		tbl.Rows = append(tbl.Rows, []string{
			d.CVE, pkg, string(d.Decision), d.DecidedWhenLevel.String(), d.Reason,
		})
	}
	tbl.Print(w)
	fmt.Fprintln(w)
}
