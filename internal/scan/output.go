package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/internal/inventory"
	"github.com/falc0n-researcher/depfuse-oss/internal/report"
	"github.com/falc0n-researcher/depfuse-oss/internal/version"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func emitOutput(opts Options, result models.ScanResult) error {
	switch opts.Format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return fmt.Errorf("encode json: %w", err)
		}
	case "html":
		if err := report.RenderHTMLWriter(os.Stdout, result); err != nil {
			return fmt.Errorf("encode html: %w", err)
		}
	case "sarif":
		if err := report.RenderSARIF(os.Stdout, result, version.String()); err != nil {
			return fmt.Errorf("encode sarif: %w", err)
		}
	default:
		ui.RenderScan(os.Stdout, result)
		if len(result.Components) > 0 {
			renderShadowDeps(os.Stdout, opts, result)
		}
	}

	if !opts.CI {
		paths := report.OutputPathsFor(opts.OutDir, result, opts.Package)
		if err := report.WriteOutputsAt(paths, []string{"md", "html"}, result); err != nil {
			return fmt.Errorf("write reports: %w", err)
		}
		if !opts.Quiet {
			fmt.Fprintf(osStderr(), "report saved to %s/%s\n", paths.Dir, paths.HTMLName)
		}
	}
	return nil
}

func osStderr() io.Writer { return os.Stderr }

func renderShadowDeps(w io.Writer, opts Options, result models.ScanResult) {
	// Package lookups already list transitive findings with Path chains in the
	// main table; the shadow summary is scan-oriented unless --tree is set.
	if opts.Package != "" && !opts.ShowTree {
		return
	}

	allFindings := append(result.Findings, result.Accepted...)
	tree := inventory.BuildTree(result.Components, allFindings)

	if tree.Stats.Shadow == 0 && tree.Stats.Orphan == 0 {
		return
	}

	ui.Section(w, "Shadow Dependencies", tree.Stats.Shadow)
	fmt.Fprintf(w, "  %s direct  ·  %s shadow  ·  %s optional/peer\n",
		ui.Bold(w, fmt.Sprint(tree.Stats.Direct)),
		ui.Bold(w, fmt.Sprint(tree.Stats.Shadow)),
		ui.Dim(w, fmt.Sprint(tree.Stats.Orphan)))
	fmt.Fprintln(w)

	if result.ShowTree {
		inventory.Render(w, tree, inventory.RenderOptions{Format: "cli"})
		return
	}

	for _, root := range tree.Roots {
		c := root.Component
		name := c.Name + "@" + c.Version
		scope := ""
		if c.Scope == models.ScopeDev {
			scope = ui.Dim(w, " [dev]")
		}
		shadow := ""
		if root.ShadowCount > 0 {
			shadow = fmt.Sprintf("  %s shadow", ui.Dim(w, fmt.Sprint(root.ShadowCount)))
		}
		cve := ""
		if root.HasCVE {
			cve = fmt.Sprintf("  %s %s",
				ui.PriorityLipgloss(w, root.WorstPriority.String()),
				ui.Danger(w, fmt.Sprintf("%d CVE", root.CVECount)))
		}
		fmt.Fprintf(w, "  %-34s%s%s%s\n", name, scope, shadow, cve)
	}
	if opts.Package == "" {
		fmt.Fprintf(w, "\n  %s\n",
			ui.Dim(w, "Use --tree to expand the full nested dependency tree."))
	}
}

func inputHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
