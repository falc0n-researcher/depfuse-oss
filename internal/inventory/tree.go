package inventory

import (
	"sort"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// Node is one package in the dependency tree.
type Node struct {
	Component     models.Component
	Children      []*Node
	Depth         int
	CVECount      int
	WorstPriority models.Priority
	HasCVE        bool
	ShadowCount   int // total transitive descendants under this node
	Orphan        bool
}

// Tree is the full structured result of BuildTree.
type Tree struct {
	// Roots are the direct dependencies (declared in package.json), each with
	// their full transitive subtree attached.
	Roots []*Node

	// Orphans are packages installed by npm but not reachable through the
	// regular dependencies chain — typically optional deps or auto-installed
	// peer deps. They are displayed in a separate section.
	Orphans []*Node

	Stats Stats
}

// Stats holds aggregate counts for the full tree.
type Stats struct {
	Total       int
	Direct      int
	Shadow      int
	Orphan      int // optional / peer deps with no tracked parent
	WithCVE     int
	CVEFindings int
	ByPriority  [5]int // index = priority value (P0=0 … P4=4)
}

// BuildTree converts a flat component list and CVE findings into a rooted
// dependency tree. Each package appears exactly once, placed under its
// primary (shortest-path) parent as recorded in Component.Path.
//
// Packages that are not direct but have no resolved parent path (optional or
// peer deps whose ancestry isn't tracked in the lockfile dependency fields)
// are collected in Tree.Orphans and can be rendered in a separate section.
func BuildTree(components []models.Component, findings []models.Finding) Tree {
	type cveInfo struct {
		count int
		worst models.Priority
	}

	// Index findings by name@version.
	cveMap := map[string]cveInfo{}
	for _, f := range findings {
		key := f.Component.Name + "@" + f.Component.Version
		info, exists := cveMap[key]
		if !exists {
			info.worst = models.PriorityP4
		}
		info.count++
		if f.Classification.Priority < info.worst {
			info.worst = f.Classification.Priority
		}
		cveMap[key] = info
	}

	// Build one Node per component, keyed by name (npm packages are name-unique
	// after lockfile deduplication).
	nodeByName := map[string]*Node{}
	for i := range components {
		c := components[i]
		key := c.Name + "@" + c.Version
		n := &Node{
			Component:     c,
			WorstPriority: models.PriorityP4,
		}
		if info, ok := cveMap[key]; ok {
			n.HasCVE = true
			n.CVECount = info.count
			n.WorstPriority = info.worst
		}
		nodeByName[c.Name] = n
	}

	// Reconstruct parent → children from Component.Path.
	// Path[-1] is always the package itself; Path[-2] (when present) is its
	// immediate parent in the shortest-path chain.
	//
	// Packages that are !Direct but have Path=["name"] (len==1) have no
	// tracked parent — they are optional deps or auto-installed peer deps that
	// npm added to the lockfile but whose ancestry isn't in the dependency
	// fields that npmDependencyPaths walks.
	childrenOf := map[string][]*Node{}
	var roots []*Node
	var orphans []*Node

	for _, n := range nodeByName {
		c := n.Component
		if c.Direct {
			roots = append(roots, n)
		} else if len(c.Path) >= 2 {
			parentName := c.Path[len(c.Path)-2]
			childrenOf[parentName] = append(childrenOf[parentName], n)
		} else {
			n.Orphan = true
			orphans = append(orphans, n)
		}
	}

	// Assign children and compute ShadowCount (total descendants) recursively.
	var attach func(n *Node, depth int) int
	attach = func(n *Node, depth int) int {
		n.Depth = depth
		children := childrenOf[n.Component.Name]
		sort.Slice(children, func(i, j int) bool {
			return children[i].Component.Name < children[j].Component.Name
		})
		n.Children = children
		total := 0
		for _, child := range children {
			total += 1 + attach(child, depth+1)
		}
		n.ShadowCount = total
		return total
	}

	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Component.Name < roots[j].Component.Name
	})
	sort.Slice(orphans, func(i, j int) bool {
		return orphans[i].Component.Name < orphans[j].Component.Name
	})
	for _, root := range roots {
		attach(root, 0)
	}

	// Compute stats.
	var stats Stats
	stats.Total = len(components)
	stats.CVEFindings = len(findings)
	for _, n := range nodeByName {
		switch {
		case n.Component.Direct:
			stats.Direct++
		case n.Orphan:
			stats.Orphan++
		default:
			stats.Shadow++
		}
		if n.HasCVE {
			stats.WithCVE++
			if int(n.WorstPriority) < len(stats.ByPriority) {
				stats.ByPriority[int(n.WorstPriority)]++
			}
		}
	}

	return Tree{Roots: roots, Orphans: orphans, Stats: stats}
}
