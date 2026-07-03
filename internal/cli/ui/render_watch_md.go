package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// RenderWatchMarkdown prints a GitHub-friendly watch digest for CI job summaries.
func RenderWatchMarkdown(w io.Writer, wr models.WatchResult) {
	fmt.Fprintf(w, "## Depfuse watch\n\n")
	if wr.InputPath != "" {
		fmt.Fprintf(w, "**Project:** `%s`\n\n", wr.InputPath)
	}
	if wr.Digest.Summary != "" {
		fmt.Fprintf(w, "%s\n\n", wr.Digest.Summary)
	}
	if len(wr.Reopened) > 0 {
		fmt.Fprintf(w, "### Needs review (%d)\n\n", len(wr.Reopened))
		for _, item := range wr.Reopened {
			fmt.Fprintf(w, "- **%s** `%s` — %s\n", item.CVE, item.Package, item.ReopenSummary)
		}
		fmt.Fprintln(w)
	}
	if len(wr.Escalated) > 0 {
		fmt.Fprintf(w, "### Escalated since last scan (%d)\n\n", len(wr.Escalated))
		for _, d := range wr.Escalated {
			fmt.Fprintf(w, "- **%s** `%s` — %s\n", d.CVEID, d.Package, d.Summary)
		}
		fmt.Fprintln(w)
	}
	if len(wr.EPSSShifts) > 0 {
		fmt.Fprintf(w, "### EPSS shifts (%d)\n\n", len(wr.EPSSShifts))
		for _, d := range wr.EPSSShifts {
			fmt.Fprintf(w, "- **%s** `%s` — %s\n", d.CVEID, d.Package, d.Summary)
		}
		fmt.Fprintln(w)
	}
	if len(wr.Silent) > 0 {
		fmt.Fprintf(w, "### Silent accepted risk (%d)\n\n", len(wr.Silent))
		fmt.Fprintf(w, "_Reopens when: %s_\n\n", strings.Join(models.ReopenPolicyLabels(), ", "))
		for _, item := range wr.Silent {
			fmt.Fprintf(w, "- `%s` %s — %s\n", item.CVE, item.Package, item.Reason)
		}
		fmt.Fprintln(w)
	}
}
