package report

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/inventory"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const depTreeFilterScript = `<script>
(function(){
  function applyDepFilter(mode){
    document.querySelectorAll('[data-dep-has-cve]').forEach(function(el){
      if(mode==='cve'){
        el.classList.toggle('dep-hidden', el.getAttribute('data-dep-has-cve')!=='true');
      } else {
        el.classList.remove('dep-hidden');
      }
    });
    document.querySelectorAll('.dep-filter-btn').forEach(function(btn){
      btn.classList.toggle('active', btn.getAttribute('data-filter')===mode);
    });
  }
  document.querySelectorAll('.dep-filter-btn').forEach(function(btn){
    btn.addEventListener('click', function(){
      applyDepFilter(btn.getAttribute('data-filter'));
    });
  });
})();
</script>`

type depTreeRenderOpts struct {
	compact      bool
	defaultOpen  bool
	maxFlatDepth int
}

func writeDepTreeSummary(b *strings.Builder, stats inventory.Stats) {
	b.WriteString(`<div class="dep-stats">`)
	writeDepStat(b, fmt.Sprint(stats.Total), "Total packages")
	writeDepStat(b, fmt.Sprint(stats.Direct), "Declared")
	writeDepStat(b, fmt.Sprint(stats.Shadow), "Nested")
	if stats.WithCVE > 0 {
		writeDepStat(b, fmt.Sprint(stats.WithCVE), "With CVEs")
	}
	if stats.Orphan > 0 {
		writeDepStat(b, fmt.Sprint(stats.Orphan), "Optional / peer")
	}
	b.WriteString(`</div>`)
}

func writeDepStat(b *strings.Builder, value, label string) {
	fmt.Fprintf(b, `<div class="dep-stat"><div class="dep-stat-value">%s</div><div class="dep-stat-label">%s</div></div>`,
		esc(value), esc(strings.ToUpper(label)))
}

func writeDepTreeToolbar(b *strings.Builder) {
	b.WriteString(`<div class="dep-toolbar">`)
	b.WriteString(`<span class="dep-toolbar-label">Show</span>`)
	b.WriteString(`<button type="button" class="dep-filter-btn active" data-filter="all">All packages</button>`)
	b.WriteString(`<button type="button" class="dep-filter-btn" data-filter="cve">CVE branches only</button>`)
	b.WriteString(`</div>`)
}

func writeDepForest(b *strings.Builder, roots []*inventory.Node, opts depTreeRenderOpts) {
	b.WriteString(`<div class="dep-forest">`)
	for _, root := range roots {
		writeDepRootCard(b, root, opts)
	}
	b.WriteString(`</div>`)
}

func writeDepOrphans(b *strings.Builder, orphans []*inventory.Node) {
	if len(orphans) == 0 {
		return
	}
	fmt.Fprintf(b, `<details class="dep-orphans-block"><summary class="dep-orphans-summary">Optional &amp; peer dependencies <span class="dep-count-chip">%d</span></summary>`, len(orphans))
	b.WriteString(`<div class="dep-orphan-grid">`)
	for _, n := range orphans {
		writeDepOrphanChip(b, n)
	}
	b.WriteString(`</div></details>`)
}

func writeDepRootCard(b *strings.Builder, n *inventory.Node, opts depTreeRenderOpts) {
	open := opts.defaultOpen || n.HasCVE || subtreeHasCVE(n)
	hasCVE := n.HasCVE || subtreeHasCVE(n)
	fmt.Fprintf(b, `<details class="dep-root"%s data-dep-has-cve="%t">`, detailsOpen(open), hasCVE)
	writeDepSummary(b, n, true)
	if len(n.Children) > 0 {
		b.WriteString(`<div class="dep-root-body"><ul class="dep-branch">`)
		for _, child := range n.Children {
			writeDepBranchNode(b, child, 1, opts)
		}
		b.WriteString(`</ul></div>`)
	}
	b.WriteString(`</details>`)
}

func writeDepSubtree(b *strings.Builder, n *inventory.Node) {
	opts := depTreeRenderOpts{compact: true, defaultOpen: true, maxFlatDepth: 2}
	b.WriteString(`<div class="dep-forest dep-forest-compact">`)
	writeDepRootCard(b, n, opts)
	b.WriteString(`</div>`)
}

func writeDepBranchNode(b *strings.Builder, n *inventory.Node, depth int, opts depTreeRenderOpts) {
	hasKids := len(n.Children) > 0
	hasCVE := n.HasCVE || subtreeHasCVE(n)

	if hasKids && depth >= opts.maxFlatDepth {
		fmt.Fprintf(b, `<li class="dep-item dep-item-branch" data-dep-has-cve="%t">`, hasCVE)
		open := n.HasCVE
		fmt.Fprintf(b, `<details class="dep-nested"%s>`, detailsOpen(open))
		writeDepSummary(b, n, false)
		b.WriteString(`<ul class="dep-branch">`)
		for _, child := range n.Children {
			writeDepBranchNode(b, child, depth+1, opts)
		}
		b.WriteString(`</ul></details></li>`)
		return
	}

	if hasKids {
		fmt.Fprintf(b, `<li class="dep-item dep-item-branch" data-dep-has-cve="%t">`, hasCVE)
		writeDepNodeRow(b, n, false)
		b.WriteString(`<ul class="dep-branch">`)
		for _, child := range n.Children {
			writeDepBranchNode(b, child, depth+1, opts)
		}
		b.WriteString(`</ul></li>`)
		return
	}

	fmt.Fprintf(b, `<li class="dep-item dep-item-leaf" data-dep-has-cve="%t">`, n.HasCVE)
	writeDepNodeRow(b, n, false)
	b.WriteString(`</li>`)
}

func writeDepSummary(b *strings.Builder, n *inventory.Node, isRoot bool) {
	c := n.Component
	cls := "dep-summary"
	if isRoot {
		cls += " dep-summary-root"
	}
	if n.HasCVE {
		cls += " dep-summary-cve"
	}
	fmt.Fprintf(b, `<summary class="%s">`, cls)
	b.WriteString(`<span class="dep-chevron" aria-hidden="true"></span>`)
	fmt.Fprintf(b, `<span class="dep-name">%s</span>`, esc(c.Name))
	fmt.Fprintf(b, `<span class="dep-ver">@%s</span>`, esc(c.Version))
	writeDepNodeMeta(b, n, isRoot)
	b.WriteString(`</summary>`)
}

func writeDepNodeRow(b *strings.Builder, n *inventory.Node, isRoot bool) {
	c := n.Component
	b.WriteString(`<div class="dep-row">`)
	fmt.Fprintf(b, `<span class="dep-name">%s</span>`, esc(c.Name))
	fmt.Fprintf(b, `<span class="dep-ver">@%s</span>`, esc(c.Version))
	writeDepNodeMeta(b, n, isRoot)
	b.WriteString(`</div>`)
}

func writeDepNodeMeta(b *strings.Builder, n *inventory.Node, isRoot bool) {
	b.WriteString(`<span class="dep-meta-group">`)
	if isRoot && n.ShadowCount > 0 {
		fmt.Fprintf(b, `<span class="dep-chip">%d nested</span>`, n.ShadowCount)
	} else if !isRoot && len(n.Children) > 0 {
		fmt.Fprintf(b, `<span class="dep-chip dep-chip-dim">+%d</span>`, len(n.Children))
	}
	if c := n.Component; c.Scope == models.ScopeDev {
		b.WriteString(`<span class="dep-chip dep-chip-dev">dev</span>`)
	}
	if n.HasCVE {
		fmt.Fprintf(b, `<span class="dep-cve-chip %s">%s · %d CVE</span>`,
			priorityClass(n.WorstPriority), esc(n.WorstPriority.String()), n.CVECount)
	} else if isRoot {
		b.WriteString(`<span class="dep-chip dep-chip-ok">clean</span>`)
	}
	b.WriteString(`</span>`)
}

func writeDepOrphanChip(b *strings.Builder, n *inventory.Node) {
	c := n.Component
	chipClass := "dep-orphan-chip"
	if n.HasCVE {
		chipClass += " dep-orphan-cve"
	}
	fmt.Fprintf(b, `<div class="%s" data-dep-has-cve="%t">`, chipClass, n.HasCVE)
	fmt.Fprintf(b, `<span class="dep-name">%s</span><span class="dep-ver">@%s</span>`, esc(c.Name), esc(c.Version))
	if n.HasCVE {
		fmt.Fprintf(b, `<span class="dep-cve-chip %s">%s</span>`, priorityClass(n.WorstPriority), esc(n.WorstPriority.String()))
	}
	b.WriteString(`</div>`)
}

func subtreeHasCVE(n *inventory.Node) bool {
	if n == nil {
		return false
	}
	if n.HasCVE {
		return true
	}
	for _, c := range n.Children {
		if subtreeHasCVE(c) {
			return true
		}
	}
	return false
}

func detailsOpen(open bool) string {
	if open {
		return ` open`
	}
	return ""
}
