package resolve

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/purl"
	"github.com/falc0n-researcher/depfuse-oss/internal/semver"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// TreeOptions configures registry-based dependency tree resolution.
type TreeOptions struct {
	Depth      int  // 0 = unlimited; 1 = root/direct only; N = max BFS depth
	IncludeDev bool // walk devDependencies of each package
	Offline    bool // use cache only; skip registry fetches
}

// TreeStats summarizes a resolved dependency tree.
type TreeStats struct {
	Total      int
	Direct     int
	Transitive int
	Root       string // name@version
}

// ResolvePackageTree resolves a single npm package and its transitive dependencies.
func ResolvePackageTree(ctx context.Context, nameVersion string, opts TreeOptions) ([]models.Component, TreeStats, error) {
	root, err := ResolvePackage(ctx, nameVersion)
	if err != nil {
		return nil, TreeStats{}, err
	}
	if opts.Depth == 1 {
		stats := TreeStats{Total: 1, Direct: 1, Root: root.Name + "@" + root.Version}
		return []models.Component{root}, stats, nil
	}
	comps, stats, err := expandTree(ctx, []models.Component{root}, opts)
	if err != nil {
		return nil, TreeStats{}, err
	}
	stats.Root = root.Name + "@" + root.Version
	return comps, stats, nil
}

// ExpandManifestTrees walks transitive dependencies for manifest-only direct components.
func ExpandManifestTrees(ctx context.Context, direct []models.Component, opts TreeOptions) ([]models.Component, error) {
	if opts.Depth == 1 || len(direct) == 0 {
		return direct, nil
	}
	comps, _, err := expandTree(ctx, direct, opts)
	return comps, err
}

func expandTree(ctx context.Context, roots []models.Component, opts TreeOptions) ([]models.Component, TreeStats, error) {
	if len(roots) == 0 {
		return nil, TreeStats{}, nil
	}

	cacheKey := treeCacheKey(roots, opts)
	if cached, ok, err := loadTreeCache(cacheKey); err == nil && ok {
		return cached, statsForComponents(cached, roots), nil
	} else if err != nil && !opts.Offline {
		// cache read failure is non-fatal when online
	}

	w := &treeWalker{
		ctx:        ctx,
		opts:       opts,
		byKey:      map[string]models.Component{},
		versions:   map[string][]string{},
		manifests:  map[string]VersionManifest{},
		visited:    map[string]bool{},
		unresolved: 0,
	}

	for _, root := range roots {
		if root.Unresolved || root.Version == "" {
			w.addComponent(root)
			continue
		}
		w.enqueue(root.Name, root.Version, root.Path, root.Scope, root.Direct, root.Manifest, 0)
	}

	if err := w.walk(); err != nil {
		if opts.Offline {
			out := w.sortedComponents()
			return out, statsForComponents(out, roots), nil
		}
		return nil, TreeStats{}, err
	}

	out := w.sortedComponents()
	if !opts.Offline {
		_ = saveTreeCache(cacheKey, out)
	}
	return out, statsForComponents(out, roots), nil
}

type treeWalker struct {
	ctx        context.Context
	opts       TreeOptions
	byKey      map[string]models.Component
	versions   map[string][]string
	manifests  map[string]VersionManifest
	visited    map[string]bool
	unresolved int
	queue      []treeItem
}

type treeItem struct {
	name     string
	version  string
	path     []string
	scope    models.Scope
	direct   bool
	manifest string
	depth    int
}

func (w *treeWalker) enqueue(name, version string, path []string, scope models.Scope, direct bool, manifest string, depth int) {
	key := name + "@" + version
	if w.visited[key] {
		w.mergeExisting(name, version, scope, direct, path)
		return
	}
	w.visited[key] = true
	w.queue = append(w.queue, treeItem{
		name: name, version: version, path: path, scope: scope,
		direct: direct, manifest: manifest, depth: depth,
	})
}

func (w *treeWalker) mergeExisting(name, version string, scope models.Scope, direct bool, path []string) {
	key := componentKey(name, version, scope)
	if existing, ok := w.byKey[key]; ok {
		if direct && !existing.Direct {
			existing.Direct = true
			w.byKey[key] = existing
		}
		return
	}
	// same name@version may appear under different scope keys — upgrade direct flag on any match
	for k, c := range w.byKey {
		if c.Name == name && c.Version == version {
			if direct && !c.Direct {
				c.Direct = true
				w.byKey[k] = c
			}
			_ = path
			return
		}
	}
}

func (w *treeWalker) walk() error {
	for len(w.queue) > 0 {
		item := w.queue[0]
		w.queue = w.queue[1:]

		comp := models.Component{
			Name:     item.name,
			Version:  item.version,
			PURL:     purl.NPM(item.name, item.version),
			Scope:    item.scope,
			Direct:   item.direct,
			Path:     append([]string(nil), item.path...),
			Manifest: item.manifest,
		}
		w.addComponent(comp)

		if w.opts.Depth > 0 && item.depth >= w.opts.Depth {
			continue
		}

		manifest, err := w.loadManifest(item.name, item.version)
		if err != nil {
			if w.opts.Offline {
				continue
			}
			return fmt.Errorf("manifest %s@%s: %w", item.name, item.version, err)
		}

		childScope := item.scope
		for depName, spec := range manifest.Dependencies {
			w.enqueueChild(depName, spec, item, childScope, models.ScopeProd)
		}
		for depName, spec := range manifest.OptionalDependencies {
			w.enqueueChild(depName, spec, item, childScope, models.ScopeProd)
		}
		if w.opts.IncludeDev || item.scope == models.ScopeDev {
			for depName, spec := range manifest.DevDependencies {
				w.enqueueChild(depName, spec, item, models.ScopeDev, models.ScopeDev)
			}
		}
	}
	return nil
}

func (w *treeWalker) enqueueChild(depName, spec string, parent treeItem, inheritedScope, depScope models.Scope) {
	depName = strings.TrimSpace(depName)
	if depName == "" {
		return
	}
	scope := inheritedScope
	if depScope == models.ScopeDev {
		scope = models.ScopeDev
	}
	version, ok := w.pinVersion(depName, spec)
	if !ok {
		w.unresolved++
		return
	}
	childPath := append(append([]string(nil), parent.path...), depName)
	w.enqueue(depName, version, childPath, scope, false, parent.manifest, parent.depth+1)
}

func (w *treeWalker) pinVersion(name, spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", false
	}
	if ver, ok := exactVersionSpec(spec); ok {
		return ver, true
	}
	versions, err := w.loadVersions(name)
	if err != nil || len(versions) == 0 {
		return "", false
	}
	best := semver.MaxSatisfying(versions, spec)
	return best, best != ""
}

func (w *treeWalker) loadVersions(name string) ([]string, error) {
	if v, ok := w.versions[name]; ok {
		return v, nil
	}
	versions, err := FetchVersions(w.ctx, name)
	if err != nil {
		return nil, err
	}
	w.versions[name] = versions
	return versions, nil
}

func (w *treeWalker) loadManifest(name, version string) (VersionManifest, error) {
	key := name + "@" + version
	if m, ok := w.manifests[key]; ok {
		return m, nil
	}
	m, err := FetchVersionManifest(w.ctx, name, version)
	if err != nil {
		return VersionManifest{}, err
	}
	w.manifests[key] = m
	return m, nil
}

func (w *treeWalker) addComponent(c models.Component) {
	key := componentKey(c.Name, c.Version, c.Scope)
	if existing, ok := w.byKey[key]; ok {
		if c.Direct && !existing.Direct {
			existing.Direct = true
		}
		if len(c.Path) < len(existing.Path) || (len(existing.Path) == 0 && len(c.Path) > 0) {
			existing.Path = c.Path
		}
		w.byKey[key] = existing
		return
	}
	w.byKey[key] = c
}

func (w *treeWalker) sortedComponents() []models.Component {
	out := make([]models.Component, 0, len(w.byKey))
	for _, c := range w.byKey {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func componentKey(name, version string, scope models.Scope) string {
	return name + "@" + version + "|" + string(scope)
}

func statsForComponents(comps []models.Component, roots []models.Component) TreeStats {
	direct := 0
	for _, c := range comps {
		if c.Direct {
			direct++
		}
	}
	root := ""
	if len(roots) == 1 {
		root = roots[0].Name + "@" + roots[0].Version
	}
	return TreeStats{
		Total:      len(comps),
		Direct:     direct,
		Transitive: len(comps) - direct,
		Root:       root,
	}
}

// FormatDependencyPath renders a human-readable import chain for receipts and CLI.
func FormatDependencyPath(comp models.Component) string {
	parts := append([]string{}, comp.Path...)
	if len(parts) == 0 {
		return comp.Name
	}
	if parts[len(parts)-1] != comp.Name {
		parts = append(parts, comp.Name)
	}
	return strings.Join(parts, " → ")
}

func exactVersionSpec(spec string) (string, bool) {
	s := strings.TrimSpace(spec)
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v"))
	if !semver.IsExact(s) {
		return "", false
	}
	return s, true
}
