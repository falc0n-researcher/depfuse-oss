package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// RenderOptions controls inventory output.
type RenderOptions struct {
	Format string // "cli" or "json"
	Depth  int    // max tree depth (0 = unlimited)
	NoCVE  bool   // skip CVE annotations
	Quiet  bool   // suppress banner
	Path   string // scanned path for display
}

// Render writes the inventory to w using the configured format.
func Render(w io.Writer, t Tree, opts RenderOptions) {
	switch opts.Format {
	case "json":
		renderJSON(w, t, opts)
	default:
		renderCLI(w, t, opts)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// CLI renderer
// ──────────────────────────────────────────────────────────────────────────────

func renderCLI(w io.Writer, t Tree, opts RenderOptions) {
	stats := t.Stats
	label := opts.Path
	if label == "" {
		label = "."
	}
	fmt.Fprintf(w, "\n  %s  ·  %s\n\n",
		ui.Title(w, "DEPENDENCY INVENTORY"),
		ui.Dim(w, label))

	// Summary line.
	fmt.Fprintf(w, "  %s packages total  ·  %s direct  ·  %s shadow",
		ui.Bold(w, fmt.Sprint(stats.Total)),
		ui.Bold(w, fmt.Sprint(stats.Direct)),
		ui.Bold(w, fmt.Sprint(stats.Shadow)))
	if stats.Orphan > 0 {
		fmt.Fprintf(w, "  ·  %s optional/peer", ui.Dim(w, fmt.Sprint(stats.Orphan)))
	}
	fmt.Fprintln(w)

	if !opts.NoCVE && stats.CVEFindings > 0 {
		pCounts := ""
		for p := 0; p <= 4; p++ {
			if n := stats.ByPriority[p]; n > 0 {
				pCounts += fmt.Sprintf("  %s×%d", ui.PriorityLipgloss(w, models.Priority(p).String()), n)
			}
		}
		fmt.Fprintf(w, "  %s CVE findings%s\n",
			ui.Danger(w, fmt.Sprint(stats.CVEFindings)), pCounts)
	}
	fmt.Fprintln(w)

	// Direct dependency trees.
	for _, root := range t.Roots {
		renderRootNode(w, root, opts)
	}

	// Optional / peer deps section (orphans).
	if len(t.Orphans) > 0 {
		fmt.Fprintf(w, "\n  %s\n", ui.Dim(w,
			fmt.Sprintf("── Optional & Peer Dependencies (%d) ─────────────────────────", len(t.Orphans))))
		fmt.Fprintf(w, "  %s\n\n", ui.Dim(w,
			"Installed by npm (optional deps / auto-installed peers) — ancestry not tracked in dependencies chain."))

		for _, n := range t.Orphans {
			c := n.Component
			scope := ""
			if c.Scope == models.ScopeDev {
				scope = " [dev]"
			}
			cveStr := ""
			if !opts.NoCVE && n.HasCVE {
				cveStr = fmt.Sprintf("  %s %s",
					ui.PriorityLipgloss(w, n.WorstPriority.String()),
					ui.Danger(w, pluralize(n.CVECount, "CVE")))
			}
			fmt.Fprintf(w, "  %s@%s%s%s\n", c.Name, c.Version, scope, cveStr)
		}
	}
	fmt.Fprintln(w)
}

// renderRootNode prints a direct dependency and its full subtree.
func renderRootNode(w io.Writer, node *Node, opts RenderOptions) {
	c := node.Component
	fmt.Fprintf(w, "  %s@%s", ui.Bold(w, c.Name), c.Version)
	if c.Scope == models.ScopeDev {
		fmt.Fprintf(w, "  %s", ui.Dim(w, "[dev]"))
	}
	if node.ShadowCount > 0 {
		fmt.Fprintf(w, "  %s", ui.Dim(w, fmt.Sprintf("%d shadow", node.ShadowCount)))
	} else {
		fmt.Fprintf(w, "  %s", ui.Dim(w, "no transitive deps"))
	}
	if !opts.NoCVE && node.HasCVE {
		fmt.Fprintf(w, "  %s %s",
			ui.PriorityLipgloss(w, node.WorstPriority.String()),
			ui.Danger(w, pluralize(node.CVECount, "CVE")))
	}
	fmt.Fprintln(w)

	for i, child := range node.Children {
		isLast := i == len(node.Children)-1
		renderChildNode(w, child, "  ", isLast, 1, opts)
	}
}

// renderChildNode prints one transitive package and recurses into its children.
func renderChildNode(w io.Writer, node *Node, prefix string, isLast bool, depth int, opts RenderOptions) {
	connector := "├── "
	childPrefix := prefix + "│   "
	if isLast {
		connector = "└── "
		childPrefix = prefix + "    "
	}

	c := node.Component
	fmt.Fprintf(w, "%s%s%s@%s", prefix, connector, c.Name, c.Version)
	if node.ShadowCount > 0 {
		fmt.Fprintf(w, "  %s", ui.Dim(w, fmt.Sprintf("+%d", node.ShadowCount)))
	}
	if !opts.NoCVE && node.HasCVE {
		fmt.Fprintf(w, "  %s %s",
			ui.PriorityLipgloss(w, node.WorstPriority.String()),
			ui.Danger(w, pluralize(node.CVECount, "CVE")))
	}
	fmt.Fprintln(w)

	if opts.Depth > 0 && depth >= opts.Depth {
		if len(node.Children) > 0 {
			fmt.Fprintf(w, "%s└── %s\n",
				childPrefix,
				ui.Dim(w, fmt.Sprintf("… %d more (use --depth to expand)", len(node.Children))))
		}
		return
	}

	for i, child := range node.Children {
		renderChildNode(w, child, childPrefix, i == len(node.Children)-1, depth+1, opts)
	}
}

func pluralize(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON renderer
// ──────────────────────────────────────────────────────────────────────────────

type jsonNode struct {
	Name          string      `json:"name"`
	Version       string      `json:"version"`
	PURL          string      `json:"purl"`
	Scope         string      `json:"scope"`
	Direct        bool        `json:"direct"`
	Path          []string    `json:"path,omitempty"`
	ShadowCount   int         `json:"shadowCount"`
	CVECount      int         `json:"cveCount,omitempty"`
	WorstPriority string      `json:"worstPriority,omitempty"`
	Children      []*jsonNode `json:"children,omitempty"`
}

type jsonOutput struct {
	Meta    jsonMeta    `json:"meta"`
	Stats   jsonStats   `json:"stats"`
	Tree    []*jsonNode `json:"tree"`
	Orphans []*jsonNode `json:"orphans,omitempty"`
}

type jsonMeta struct {
	Path string `json:"path"`
}

type jsonStats struct {
	Total       int `json:"total"`
	Direct      int `json:"direct"`
	Shadow      int `json:"shadow"`
	Orphan      int `json:"orphan"`
	CVEFindings int `json:"cveFindings"`
	WithCVE     int `json:"packagesWithCVE"`
}

func renderJSON(w io.Writer, t Tree, opts RenderOptions) {
	var toJSON func(n *Node) *jsonNode
	toJSON = func(n *Node) *jsonNode {
		jn := &jsonNode{
			Name:        n.Component.Name,
			Version:     n.Component.Version,
			PURL:        n.Component.PURL,
			Scope:       string(n.Component.Scope),
			Direct:      n.Component.Direct,
			Path:        n.Component.Path,
			ShadowCount: n.ShadowCount,
		}
		if n.HasCVE && !opts.NoCVE {
			jn.CVECount = n.CVECount
			jn.WorstPriority = n.WorstPriority.String()
		}
		for _, child := range n.Children {
			jn.Children = append(jn.Children, toJSON(child))
		}
		return jn
	}

	stats := t.Stats
	out := jsonOutput{
		Meta: jsonMeta{Path: opts.Path},
		Stats: jsonStats{
			Total:       stats.Total,
			Direct:      stats.Direct,
			Shadow:      stats.Shadow,
			Orphan:      stats.Orphan,
			CVEFindings: stats.CVEFindings,
			WithCVE:     stats.WithCVE,
		},
	}
	for _, root := range t.Roots {
		out.Tree = append(out.Tree, toJSON(root))
	}
	for _, orp := range t.Orphans {
		out.Orphans = append(out.Orphans, toJSON(orp))
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// ──────────────────────────────────────────────────────────────────────────────
// Summary table
// ──────────────────────────────────────────────────────────────────────────────

// RenderSummaryTable prints a flat table of direct deps with their shadow and
// CVE counts.
func RenderSummaryTable(w io.Writer, t Tree, opts RenderOptions) {
	fmt.Fprintf(w, "\n  %s\n\n", ui.Title(w, "DIRECT DEPENDENCY SUMMARY"))

	header := fmt.Sprintf("  %-30s  %-10s  %-8s  %-8s  %s",
		"PACKAGE", "VERSION", "SCOPE", "SHADOW", "CVE")
	fmt.Fprintln(w, ui.Dim(w, header))
	fmt.Fprintln(w, ui.Dim(w, "  "+strings.Repeat("─", 70)))

	for _, root := range t.Roots {
		c := root.Component
		cveCol := ""
		if !opts.NoCVE && root.HasCVE {
			cveCol = fmt.Sprintf("%s %s",
				ui.PriorityLipgloss(w, root.WorstPriority.String()),
				pluralize(root.CVECount, "CVE"))
		} else if !opts.NoCVE {
			cveCol = ui.Dim(w, "none")
		}
		fmt.Fprintf(w, "  %-30s  %-10s  %-8s  %-8d  %s\n",
			c.Name, c.Version, string(c.Scope), root.ShadowCount, cveCol)
	}
	fmt.Fprintln(w)

	if t.Stats.Orphan > 0 {
		fmt.Fprintf(w, "  %s\n\n",
			ui.Dim(w, fmt.Sprintf("+ %d optional/peer packages (use --tree to expand)", t.Stats.Orphan)))
	}
}
