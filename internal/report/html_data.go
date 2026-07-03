package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/inventory"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

var slugSanitizer = regexp.MustCompile(`[^a-z0-9]+`)

type dashboardData struct {
	Packages []packagePageData
}

type packagePageData struct {
	Slug        string
	Key         string
	Name        string
	Version     string
	Component   models.Component
	Context     *models.PackageContext
	Findings    []models.Finding
	Node        *inventory.Node
	CVECount    int
	Worst       models.Priority
	Shadow      int
	TreePreview string
}

func buildDashboardData(result models.ScanResult) dashboardData {
	allFindings := append(append([]models.Finding{}, result.Findings...), result.Accepted...)
	tree := inventory.BuildTree(result.Components, allFindings)
	nodeByName := map[string]*inventory.Node{}
	for _, root := range tree.Roots {
		indexNodes(root, nodeByName)
	}
	for _, orp := range tree.Orphans {
		nodeByName[orp.Component.Name] = orp
	}

	pkgMap := map[string]*packagePageData{}
	for _, f := range allFindings {
		key := f.Component.Name + "@" + f.Component.Version
		p, ok := pkgMap[key]
		if !ok {
			p = &packagePageData{
				Key:       key,
				Slug:      packageSlug(f.Component.Name, f.Component.Version),
				Name:      f.Component.Name,
				Version:   f.Component.Version,
				Component: f.Component,
				Context:   packageContextFor(f, result.Packages),
				Worst:     models.PriorityP4,
			}
			if n, ok := nodeByName[f.Component.Name]; ok {
				p.Node = n
				p.Shadow = n.ShadowCount
			}
			pkgMap[key] = p
		}
		p.Findings = append(p.Findings, f)
		p.CVECount++
		if f.Classification.Priority < p.Worst {
			p.Worst = f.Classification.Priority
		}
		if p.Context == nil {
			p.Context = packageContextFor(f, result.Packages)
		}
	}

	for key, p := range pkgMap {
		s := *p
		if s.TreePreview == "" && result.Meta.ResolvedPackage != "" && strings.HasPrefix(s.Version, "<") {
			if strings.HasPrefix(result.Meta.ResolvedPackage, s.Name+"@") {
				s.TreePreview = result.Meta.ResolvedPackage
			}
		}
		pkgMap[key] = &s
	}

	// Include direct dependencies without CVEs so every declared dep gets a bible page.
	for _, c := range result.Components {
		if !c.Direct {
			continue
		}
		key := c.Name + "@" + c.Version
		if _, ok := pkgMap[key]; ok {
			continue
		}
		p := &packagePageData{
			Key:       key,
			Slug:      packageSlug(c.Name, c.Version),
			Name:      c.Name,
			Version:   c.Version,
			Component: c,
			Worst:     models.PriorityP4,
		}
		if ctx, ok := result.Packages[c.Name]; ok {
			copy := ctx
			p.Context = &copy
		}
		if n, ok := nodeByName[c.Name]; ok {
			p.Node = n
			p.Shadow = n.ShadowCount
		}
		pkgMap[key] = p
	}

	packages := make([]packagePageData, 0, len(pkgMap))
	for _, p := range pkgMap {
		sortFindingsByPriority(p.Findings)
		packages = append(packages, *p)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Worst != packages[j].Worst {
			return packages[i].Worst < packages[j].Worst
		}
		if packages[i].CVECount != packages[j].CVECount {
			return packages[i].CVECount > packages[j].CVECount
		}
		return packages[i].Key < packages[j].Key
	})

	return dashboardData{Packages: packages}
}

func indexNodes(n *inventory.Node, out map[string]*inventory.Node) {
	out[n.Component.Name] = n
	for _, c := range n.Children {
		indexNodes(c, out)
	}
}

func packageSlug(name, version string) string {
	s := strings.ToLower(name + "-" + version)
	s = slugSanitizer.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

func sortFindingsByPriority(findings []models.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Classification.Priority != b.Classification.Priority {
			return a.Classification.Priority < b.Classification.Priority
		}
		ai, bi := advisoryID(a), advisoryID(b)
		if ai != bi {
			return ai < bi
		}
		return a.Component.Name < b.Component.Name
	})
}

func advisoryID(f models.Finding) string {
	if f.CveMatch.CVEID != "" {
		return f.CveMatch.CVEID
	}
	if f.CveMatch.GHSAID != "" {
		return f.CveMatch.GHSAID
	}
	return f.CveMatch.OSVID
}

func cvePrimaryURL(c models.CveMatch) string {
	if c.CVEID != "" && strings.HasPrefix(c.CVEID, "CVE-") {
		return "https://nvd.nist.gov/vuln/detail/" + c.CVEID
	}
	ghsa := c.GHSAID
	if ghsa == "" && strings.HasPrefix(c.CVEID, "GHSA-") {
		ghsa = c.CVEID
	}
	if ghsa != "" {
		return "https://github.com/advisories/" + ghsa
	}
	if id := osvAdvisoryID(c); id != "" {
		return osvWebURL(id)
	}
	return ""
}

func cveOSVURL(c models.CveMatch) string {
	id := osvAdvisoryID(c)
	if id == "" {
		return ""
	}
	return osvWebURL(id)
}

func osvAdvisoryID(c models.CveMatch) string {
	if c.GHSAID != "" {
		return c.GHSAID
	}
	if strings.HasPrefix(c.OSVID, "GHSA-") || strings.HasPrefix(c.OSVID, "CVE-") {
		return c.OSVID
	}
	if strings.HasPrefix(c.CVEID, "GHSA-") || strings.HasPrefix(c.CVEID, "CVE-") {
		return c.CVEID
	}
	return c.OSVID
}

func osvWebURL(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	return "https://osv.dev/vulnerability/" + id
}

func dependencyRoleLabel(c models.Component) string {
	if c.Scope == models.ScopeDev {
		return "Dev dependency"
	}
	if c.Direct {
		return "Declared dependency"
	}
	if len(c.Path) >= 2 {
		return fmt.Sprintf("Transitive via %s", c.Path[0])
	}
	return "Transitive dependency"
}

func countPackagesWithCVE(packages []packagePageData) int {
	n := 0
	for _, p := range packages {
		if p.CVECount > 0 {
			n++
		}
	}
	return n
}
