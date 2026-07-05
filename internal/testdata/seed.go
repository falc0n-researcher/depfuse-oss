package testdata

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/match"
	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// DemoFixtureRoot is the primary offline demo and CFP scan target.
const DemoFixtureRoot = "demo_package"

// SeedIntelDB creates or updates a pinned intelligence snapshot for offline tests and demos.
func SeedIntelDB(dbPath string, fixtureRoots ...string) error {
	if len(fixtureRoots) == 0 {
		fixtureRoots = []string{DemoFixtureRoot}
	}

	store, err := intel.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	defer store.Close()

	if err := intel.SeedDemoData(store); err != nil {
		return fmt.Errorf("seed demo data: %w", err)
	}
	if err := store.SetCollectedMeta(); err != nil {
		return fmt.Errorf("set snapshot meta: %w", err)
	}

	client := &match.Client{}
	seen := map[string]bool{}
	for _, root := range fixtureRoots {
		comps, err := resolve.Resolve(resolve.Options{Root: root})
		if err != nil {
			return fmt.Errorf("resolve %s: %w", root, err)
		}
		matches, err := client.MatchComponents(context.Background(), comps)
		if err != nil {
			return fmt.Errorf("osv match %s: %w", root, err)
		}
		for _, cm := range matches {
			key := cm.Component.Name + "@" + cm.Component.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(cm.Matches) == 0 {
				continue
			}
			if err := store.PutOSVCache("npm", cm.Component.Name, cm.Component.Version, cm.Matches); err != nil {
				return fmt.Errorf("cache osv for %s: %w", key, err)
			}
		}
	}
	if err := intel.SyncAliasesFromOSVCache(store); err != nil {
		return err
	}
	return seedPackageMeta(context.Background(), store, fixtureRoots)
}

// DefaultPaths returns standard testdata locations relative to repo root.
func DefaultPaths(repoRoot string) (dbPath, fixtureRoot string) {
	return filepath.Join(repoRoot, "testdata", "intel.db"),
		filepath.Join(repoRoot, DemoFixtureRoot)
}

// DemoPaths returns paths for CFP booth demo (self-contained under demo_package).
func DemoPaths(repoRoot string) (dbPath, fixtureRoot string) {
	return filepath.Join(repoRoot, DemoFixtureRoot, "intel.db"),
		filepath.Join(repoRoot, DemoFixtureRoot)
}

// EnsureIntelDB creates testdata/intel.db when missing.
func EnsureIntelDB(repoRoot string) error {
	dbPath, _ := DefaultPaths(repoRoot)
	if _, err := os.Stat(dbPath); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}
	return SeedIntelDB(dbPath, filepath.Join(repoRoot, DemoFixtureRoot), filepath.Join(repoRoot, "testdata/express-app"), filepath.Join(repoRoot, "testdata/next-app"))
}

// EnsureDemoIntelDB creates demo_package/intel.db when missing.
func EnsureDemoIntelDB(repoRoot string) error {
	dbPath, fixtureRoot := DemoPaths(repoRoot)
	if _, err := os.Stat(dbPath); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}
	return SeedIntelDB(dbPath, fixtureRoot)
}

// seedPackageMeta caches npm registry metadata for fixture components and common
// package-mode lookup trees so offline HTML reports include ecosystem context.
func seedPackageMeta(ctx context.Context, store *intel.Store, fixtureRoots []string) error {
	names := map[string]struct{}{}
	addComps := func(comps []models.Component) {
		for _, c := range comps {
			if c.Name != "" && !c.Unresolved {
				names[c.Name] = struct{}{}
			}
		}
	}
	for _, root := range fixtureRoots {
		comps, err := resolve.Resolve(resolve.Options{Root: root, Ctx: ctx})
		if err != nil {
			return fmt.Errorf("resolve %s for package meta: %w", root, err)
		}
		addComps(comps)
	}
	for _, pkg := range []string{"next@15.1.0", "express@4.17.1", "jquery@3.2.1"} {
		comps, _, err := resolve.ResolvePackageTree(ctx, pkg, resolve.TreeOptions{})
		if err != nil {
			return fmt.Errorf("resolve tree %s for package meta: %w", pkg, err)
		}
		addComps(comps)
	}
	if len(names) == 0 {
		return nil
	}
	list := make([]string, 0, len(names))
	for name := range names {
		list = append(list, name)
	}
	sort.Strings(list)
	if _, err := pkgmeta.Lookup(ctx, store, false, list...); err != nil {
		return fmt.Errorf("lookup package meta: %w", err)
	}
	return nil
}
