package resolve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/purl"
	"github.com/falc0n-researcher/depfuse-oss/internal/resolve/lockfile"
	"github.com/falc0n-researcher/depfuse-oss/internal/semver"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// Options configures dependency resolution.
type Options struct {
	Root       string
	Ctx        context.Context
	Offline    bool // when true, range specs are not resolved against the npm registry
	TreeDepth  int  // 0 = full transitive tree; 1 = direct/root only
	IncludeDev bool // include devDependencies when walking registry trees
}

type resolveGroup struct {
	lockKind  string
	lockPath  string
	manifests []string
}

// Resolve walks manifests and lockfiles under root and returns deduplicated components.
func Resolve(opts Options) ([]models.Component, error) {
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, err
	}

	manifests, err := discoverManifests(root)
	if err != nil {
		return nil, err
	}

	groups := groupManifests(root, manifests)

	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	byKey := map[string]models.Component{}
	treeOpts := TreeOptions{Depth: opts.TreeDepth, IncludeDev: opts.IncludeDev, Offline: opts.Offline}
	for _, g := range groups {
		comps, err := resolveManifestGroup(root, g)
		if err != nil {
			return nil, err
		}
		pinManifestVersions(ctx, opts.Offline, comps)
		if g.lockPath == "" && opts.TreeDepth != 1 {
			expanded, err := ExpandManifestTrees(ctx, comps, treeOpts)
			if err != nil {
				return nil, err
			}
			comps = expanded
		}
		for _, c := range comps {
			key := c.Name + "@" + c.Version + "|" + string(c.Scope)
			if existing, ok := byKey[key]; ok {
				if c.Direct && !existing.Direct {
					byKey[key] = c
				}
				continue
			}
			byKey[key] = c
		}
	}

	out := make([]models.Component, 0, len(byKey))
	for _, c := range byKey {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// pinManifestVersions resolves range specs from manifest-only components to a
// concrete installed version via the npm registry. Exact specs are already
// pinned by ParseManifestOnly. Offline, or on registry failure, the component
// stays Unresolved so it is excluded from matching rather than silently cleared.
func pinManifestVersions(ctx context.Context, offline bool, comps []models.Component) {
	if offline {
		for i := range comps {
			c := &comps[i]
			if c.Unresolved && c.Spec != "" {
				c.UnresolvedReason = ReasonOfflineMode
			}
		}
		return
	}
	cache := map[string][]string{}
	errCache := map[string]error{}
	for i := range comps {
		c := &comps[i]
		if !c.Unresolved || c.Spec == "" {
			continue
		}
		versions, ok := cache[c.Name]
		if !ok {
			if err, tried := errCache[c.Name]; tried {
				c.UnresolvedReason = registryErrorReason(err)
				continue
			}
			v, err := FetchVersions(ctx, c.Name)
			if err != nil {
				errCache[c.Name] = err
				c.UnresolvedReason = registryErrorReason(err)
				continue
			}
			versions = v
			cache[c.Name] = v
		}
		if best := semver.MaxSatisfying(versions, c.Spec); best != "" {
			c.Version = best
			c.PURL = purl.NPM(c.Name, best)
			c.Unresolved = false
			c.UnresolvedReason = ""
			continue
		}
	}
}

func registryErrorReason(err error) string {
	var re *RegistryError
	if errors.As(err, &re) {
		return re.Reason
	}
	return ReasonNetworkError
}

func discoverManifests(root string) ([]string, error) {
	seen := map[string]bool{}
	var manifests []string

	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		if _, err := os.Stat(p); err != nil {
			return
		}
		seen[p] = true
		manifests = append(manifests, p)
	}

	rootManifest := filepath.Join(root, "package.json")
	add(rootManifest)

	if patterns, err := DiscoverWorkspaces(rootManifest); err != nil {
		return nil, err
	} else if len(patterns) > 0 {
		ws, err := ExpandWorkspaceGlobs(root, patterns)
		if err != nil {
			return nil, err
		}
		for _, m := range ws {
			add(m)
		}
	} else {
		// Fallback: packages/*/package.json when workspaces field is absent.
		packagesDir := filepath.Join(root, "packages")
		entries, err := os.ReadDir(packagesDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				add(filepath.Join(packagesDir, e.Name(), "package.json"))
			}
		}
	}

	if len(manifests) == 0 {
		return nil, fmt.Errorf("no package.json found under %s", root)
	}
	sort.Strings(manifests)
	return manifests, nil
}

func groupManifests(root string, manifests []string) []resolveGroup {
	byLock := make(map[string]*resolveGroup)
	var solo []resolveGroup

	for _, manifestPath := range manifests {
		dir := filepath.Dir(manifestPath)
		kind, lockPath := FindLockfile(dir, root)
		if lockPath == "" {
			solo = append(solo, resolveGroup{manifests: []string{manifestPath}})
			continue
		}
		g, ok := byLock[lockPath]
		if !ok {
			g = &resolveGroup{lockKind: kind, lockPath: lockPath}
			byLock[lockPath] = g
		}
		g.manifests = append(g.manifests, manifestPath)
	}

	out := make([]resolveGroup, 0, len(byLock)+len(solo))
	for _, g := range byLock {
		sort.Strings(g.manifests)
		out = append(out, *g)
	}
	out = append(out, solo...)
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].manifests) == 0 {
			return true
		}
		if len(out[j].manifests) == 0 {
			return false
		}
		return out[i].manifests[0] < out[j].manifests[0]
	})
	return out
}

func resolveManifestGroup(root string, g resolveGroup) ([]models.Component, error) {
	deps, err := mergeManifestDeps(g.manifests)
	if err != nil {
		return nil, err
	}
	primary := g.manifests[0]

	if g.lockPath == "" {
		return lockfile.ParseManifestOnly(primary, deps)
	}

	lockRoot := filepath.Dir(g.lockPath)
	var comps []models.Component
	switch g.lockKind {
	case "npm":
		comps, err = lockfile.ParseNPM(primary, deps, g.lockPath)
	case "yarn":
		comps, err = lockfile.ParseYarn(primary, deps, g.lockPath)
	case "pnpm":
		comps, err = lockfile.ParsePNPM(primary, deps, g.lockPath)
	case "bun":
		comps, err = lockfile.ParseBun(primary, deps, g.lockPath)
	default:
		return lockfile.ParseManifestOnly(primary, deps)
	}
	if err != nil {
		return nil, err
	}
	if rel, err := filepath.Rel(root, lockRoot); err == nil && rel != "." {
		for i := range comps {
			comps[i].LockfileRoot = rel
		}
	}
	return comps, err
}

func mergeManifestDeps(manifestPaths []string) (lockfile.ManifestDeps, error) {
	merged := lockfile.ManifestDeps{
		Prod:  map[string]bool{},
		Dev:   map[string]bool{},
		Specs: map[string]string{},
	}
	for _, p := range manifestPaths {
		deps, err := lockfile.LoadManifestDeps(p)
		if err != nil {
			return lockfile.ManifestDeps{}, fmt.Errorf("%s: %w", p, err)
		}
		for k := range deps.Prod {
			merged.Prod[k] = true
		}
		for k := range deps.Dev {
			merged.Dev[k] = true
		}
		for k, v := range deps.Specs {
			if _, ok := merged.Specs[k]; !ok {
				merged.Specs[k] = v
			}
		}
	}
	return merged, nil
}

// FindLockfile walks from dir up to stopAt looking for pnpm/yarn/npm lockfiles.
func FindLockfile(dir, stopAt string) (kind, path string) {
	stopAt, _ = filepath.Abs(stopAt)
	dir, _ = filepath.Abs(dir)

	for {
		kind, path = pickLockfileInDir(dir)
		if path != "" {
			return kind, path
		}
		if dir == stopAt {
			return "", ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ""
		}
		dir = parent
	}
}

func pickLockfileInDir(dir string) (kind, path string) {
	candidates := []struct {
		kind string
		name string
	}{
		{"pnpm", "pnpm-lock.yaml"},
		{"bun", "bun.lock"},
		{"yarn", "yarn.lock"},
		{"npm", "package-lock.json"},
		{"npm", "npm-shrinkwrap.json"},
	}
	for _, c := range candidates {
		p := filepath.Join(dir, c.name)
		if _, err := os.Stat(p); err == nil {
			return c.kind, p
		}
	}
	return "", ""
}

// ResolvePackage resolves a single npm package name@version.
// When version is "latest", the semver is fetched from the npm registry.
func ResolvePackage(ctx context.Context, nameVersion string) (models.Component, error) {
	name := strings.TrimSpace(nameVersion)
	version := "latest"
	if idx := strings.LastIndex(name, "@"); idx > 0 {
		version = name[idx+1:]
		name = name[:idx]
	}
	if name == "" {
		return models.Component{}, fmt.Errorf("package name required")
	}
	name = NormalizeNPMPackageName(ctx, name)
	if version == "latest" {
		resolved, err := FetchLatestVersion(ctx, name)
		if err != nil {
			return models.Component{}, err
		}
		version = resolved
	}
	return models.Component{
		Name:    name,
		Version: version,
		PURL:    fmt.Sprintf("pkg:npm/%s@%s", name, version),
		Scope:   models.ScopeProd,
		Direct:  true,
		Path:    []string{name},
	}, nil
}
