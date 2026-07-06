package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/internal/decisions"
	"github.com/falc0n-researcher/depfuse-oss/internal/gitrepo"
	"github.com/falc0n-researcher/depfuse-oss/internal/history"
	"github.com/falc0n-researcher/depfuse-oss/internal/ignore"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel/collector"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel/snapshot"
	"github.com/falc0n-researcher/depfuse-oss/internal/match"
	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// Options configures a scan run.
type Options struct {
	Path           string
	RepoURL        string
	RepoRef        string
	Package        string
	DBPath         string
	Offline        bool
	Format         string
	OutDir         string
	CI             bool
	FailOn         string
	Quiet          bool
	Verbose        bool
	ShowSuppressed bool
	Delta          bool
	NoHistory      bool
	SkipEmit       bool
	TreeDepth      int  // 0 = full tree; 1 = root/direct only
	IncludeDev     bool // walk devDependencies in registry trees
	ShowTree       bool // expand full nested shadow dep tree in CLI output

	// FailOnCoverageWarning also exits 1 on partial coverage (embedded
	// weaponized-only snapshot, registry-resolved-not-lockfile-pinned tree),
	// not just on incomplete coverage (which always exits 1).
	FailOnCoverageWarning bool
}

// Runner executes the full scan pipeline.
type Runner struct {
	Store *intel.Store
}

// Run executes resolve → match → classify → brief → verdict → report.
func (r *Runner) Run(ctx context.Context, opts Options) (models.ScanResult, int, error) {
	start := time.Now()
	if ui.ShowBanner(opts.Quiet, opts.Format) {
		ui.BeginCommand(osStderr(), opts.Quiet, "exploit-risk dependency scan")
	}
	prog := ui.NewProgress(osStderr(), opts.Quiet)

	done := prog.Step("Intelligence")
	store, err := r.openStore(ctx, opts)
	if err != nil {
		done("failed")
		return models.ScanResult{}, 1, err
	}
	done("ready")
	defer store.Close()

	if opts.Offline && !store.HasOSVNPM() && !store.HasOSVCache() {
		fmt.Fprintf(osStderr(), "warning: offline mode (DEPFUSE_OFFLINE) but this intel.db has no offline advisory data — matches may be empty; run `depfuse collect`\n")
	}

	done = prog.Step("Resolve dependencies")
	root, components, treeStats, err := r.resolveInput(ctx, opts)
	if err != nil {
		done("failed")
		return models.ScanResult{}, 1, err
	}
	done(fmt.Sprintf("%d packages", len(components)))

	done = prog.Step("Match vulnerabilities")
	componentMatches, osvStats, err := r.matchCVEs(ctx, store, opts, components)
	if err != nil {
		done("failed")
		return models.ScanResult{}, 1, err
	}
	matchCount := 0
	for _, cm := range componentMatches {
		matchCount += len(cm.Matches)
	}
	done(fmt.Sprintf("%d CVE matches", matchCount))

	done = prog.Step("Classify & verdict")
	findings, err := r.classifyAndVerdict(store, componentMatches, opts)
	if err != nil {
		done("failed")
		return models.ScanResult{}, 1, err
	}
	done(fmt.Sprintf("%d findings", len(findings)))

	done = prog.Step("Package context")
	var alwaysPkg []string
	if opts.Package != "" {
		if treeStats.Root != "" {
			if idx := strings.Index(treeStats.Root, "@"); idx > 0 {
				alwaysPkg = []string{treeStats.Root[:idx]}
			}
		} else if len(components) > 0 {
			alwaysPkg = []string{components[0].Name}
		}
	}
	pkgMap := attachPackageContext(ctx, store, opts.Offline, findings, components, alwaysPkg...)
	done(fmt.Sprintf("%d packages", len(pkgMap)))

	rules, _ := ignore.Load(root)
	findings = ignore.Apply(findings, rules)
	preActive, ignored := ignore.Partition(findings)

	decFile, _ := decisions.Load(root)
	active, accepted, _ := decisions.Apply(store, preActive, decFile)

	result := buildResult(store, root, opts, components, active, ignored, accepted, start, osvStats, treeStats)
	result.ShowIgnored = opts.ShowSuppressed
	result.Verbose = opts.Verbose
	result.ShowTree = opts.ShowTree
	result.Packages = pkgMap

	hs := &history.Store{Intel: store}
	if opts.Delta {
		if prev, prevAt, err := hs.LoadPrevious(result.Meta.InputHash); err == nil && len(prev) > 0 {
			d := history.ComputeDelta(prev, active, prevAt)
			result.Delta = &d
		}
	}
	if !opts.NoHistory {
		snaps := make([]models.HistorySnapshot, 0, len(active))
		for _, f := range active {
			snaps = append(snaps, history.ToSnapshot(f))
		}
		if err := hs.Save(result.Meta.InputHash, result.Meta.SnapshotVersion, result.Meta.Timestamp, snaps); err != nil {
			fmt.Fprintf(osStderr(), "warning: could not save scan history: %v\n", err)
		}
	}

	if opts.Package != "" && treeStats.Root != "" {
		result.Meta.ResolvedPackage = treeStats.Root
		if name := alwaysPkgRoot(alwaysPkg); name != "" {
			result.Meta.PackageContext = primaryPackageContext(active, pkgMap, name)
		}
		if len(active) == 0 && !opts.Offline {
			matcher := &match.Client{Offline: opts.Offline, OfflineDB: store}
			if len(components) > 0 {
				catalog, err := matcher.QueryPackageCatalog(ctx, components[0].Name)
				if err == nil && len(catalog) > 0 {
					result.Meta.PackageNote = match.FormatUnaffectedPackageNote(components[0], catalog)
				}
			}
		}
	}

	exitCode := scanExitCode(opts, result, active, ignored)
	if !opts.SkipEmit {
		if err := emitOutput(opts, result); err != nil {
			return result, 1, err
		}
	}

	return result, exitCode, nil
}

func (r *Runner) resolveInput(ctx context.Context, opts Options) (root string, components []models.Component, tree resolve.TreeStats, err error) {
	root = opts.Path
	repoURL := opts.RepoURL
	if repoURL == "" && gitrepo.IsGitHubURL(root) {
		repoURL = root
		root = "."
	}
	if repoURL != "" {
		root, err = gitrepo.Clone(repoURL, opts.RepoRef)
		if err != nil {
			return "", nil, tree, err
		}
	}

	if opts.Package != "" {
		treeOpts := resolve.TreeOptions{
			Depth: opts.TreeDepth, IncludeDev: opts.IncludeDev, Offline: opts.Offline,
		}
		components, tree, err = resolve.ResolvePackageTree(ctx, opts.Package, treeOpts)
		if err != nil {
			return "", nil, tree, err
		}
		return root, components, tree, nil
	}

	if root == "" {
		root = "."
	}
	root, err = resolve.NormalizeScanRoot(root)
	if err != nil {
		return "", nil, tree, err
	}
	components, err = resolve.Resolve(resolve.Options{
		Root: root, Ctx: ctx, Offline: opts.Offline,
		TreeDepth: opts.TreeDepth, IncludeDev: opts.IncludeDev,
	})
	if err != nil {
		return root, nil, tree, err
	}
	tree = resolveTreeStatsFromComponents(components)
	if resolve.UsesManifestOnlyResolution(components) {
		unresolved := resolve.UnresolvedComponents(components)
		if tree.Transitive > 0 {
			fmt.Fprintf(osStderr(), "info: no lockfile — resolved %d packages (%d transitive) via npm registry dependency tree\n",
				tree.Total, tree.Transitive)
		} else if len(unresolved) == 0 {
			fmt.Fprintf(osStderr(), "warning: no lockfile found — resolved %d direct dependencies from package.json ranges; transitive dependencies are not scanned\n", len(components))
		} else if opts.Offline {
			fmt.Fprintf(osStderr(), "warning: no lockfile found and DEPFUSE_OFFLINE set — %d/%d dependencies with range specs could not be pinned and were NOT scanned; commit a lockfile or unset DEPFUSE_OFFLINE\n", len(unresolved), len(components))
		} else {
			fmt.Fprintf(osStderr(), "warning: no lockfile found — %d/%d dependencies could not be pinned to a concrete version and were NOT scanned: %s\n", len(unresolved), len(components), unresolvedNames(unresolved))
		}
	}
	return root, components, tree, err
}

func resolveTreeStatsFromComponents(comps []models.Component) resolve.TreeStats {
	direct := 0
	for _, c := range comps {
		if c.Direct {
			direct++
		}
	}
	return resolve.TreeStats{Total: len(comps), Direct: direct, Transitive: len(comps) - direct}
}

func alwaysPkgRoot(names []string) string {
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

func unresolvedNames(comps []models.Component) string {
	names := make([]string, 0, len(comps))
	for _, c := range comps {
		spec := c.Spec
		if spec == "" {
			spec = "*"
		}
		names = append(names, fmt.Sprintf("%s@%s", c.Name, spec))
	}
	return strings.Join(names, ", ")
}

func (r *Runner) matchCVEs(ctx context.Context, store *intel.Store, opts Options, components []models.Component) ([]match.ComponentMatch, match.Stats, error) {
	matcher := &match.Client{Offline: opts.Offline, OfflineDB: store}
	matches, err := matcher.MatchComponents(ctx, components)
	if err != nil {
		return nil, match.Stats{}, err
	}
	for _, cm := range matches {
		if err := matcher.EnrichFromQuery(ctx, cm.Component, cm.Matches); err != nil {
			return nil, match.Stats{}, err
		}
		for i := range cm.Matches {
			_ = intel.EnrichCveMatch(ctx, store, &cm.Matches[i], opts.Offline)
		}
		_ = store.PutOSVCache("npm", cm.Component.Name, cm.Component.Version, cm.Matches)
	}
	return matches, matcher.Stats, nil
}

func (r *Runner) openStore(ctx context.Context, opts Options) (*intel.Store, error) {
	if r.Store != nil {
		return r.Store, nil
	}

	dbPath := opts.DBPath
	if dbPath == "" {
		dbPath = intel.ResolvedPath()
	}

	if !opts.Offline && !intel.SkipAutoCollect() {
		prog := ui.NewProgress(osStderr(), opts.Quiet)
		if err := collector.EnsureFresh(ctx, dbPath, opts.Quiet, prog.Step); err != nil {
			return nil, err
		}
	}

	if _, statErr := os.Stat(dbPath); os.IsNotExist(statErr) {
		if ok, _ := snapshot.Extract(dbPath); ok {
			fmt.Fprintf(osStderr(), "no intel.db found — using the built-in weaponized snapshot. Run `depfuse collect` for the full advisory inventory.\n")
		}
	}
	store, err := intel.Open(dbPath)
	if err != nil {
		return nil, err
	}
	has, err := store.HasData()
	if err != nil {
		store.Close()
		return nil, err
	}
	if !has {
		store.Close()
		return nil, fmt.Errorf("intelligence database is empty — run `depfuse collect` first")
	}
	return store, nil
}
