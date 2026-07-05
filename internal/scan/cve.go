package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/brief"
	"github.com/falc0n-researcher/depfuse-oss/internal/classify"
	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/report"
	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/internal/semver"
	"github.com/falc0n-researcher/depfuse-oss/internal/verdict"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// RunCVE classifies a single CVE using the intelligence database (no npm resolution).
func (r *Runner) RunCVE(ctx context.Context, cveID string, opts Options) (models.ScanResult, error) {
	start := time.Now()
	cveID = strings.TrimSpace(cveID)
	if cveID == "" {
		return models.ScanResult{}, fmt.Errorf("CVE id required")
	}

	if ui.ShowBanner(opts.Quiet, opts.Format) {
		ui.BeginCommand(osStderr(), opts.Quiet, "exploit-risk dependency scan")
	}
	prog := ui.NewProgress(osStderr(), opts.Quiet)
	done := prog.Step("Intelligence")
	store, err := r.openStore(ctx, opts)
	if err != nil {
		done("failed")
		return models.ScanResult{}, err
	}
	done("ready")
	defer store.Close()

	done = prog.Step("Classify CVE")
	cm := models.CveMatch{CVEID: cveID}
	_ = intel.EnrichCveMatch(ctx, store, &cm, opts.Offline)
	if cm.CVEID == "" {
		cm.CVEID = cveID
	}

	// Surface the affected npm package(s). The OSV /vulns/CVE record often omits
	// the npm ecosystem mapping (it lives on the GHSA record); the local OSV npm
	// alias index carries it and works online and offline.
	if len(cm.NPMAffectedPackages()) == 0 {
		ids := append([]string{cm.CVEID, cm.OSVID, cm.GHSAID}, cm.Aliases...)
		if aff := store.OSVNPMPackagesForAlias(ids...); len(aff) > 0 {
			cm.AffectedPackages = append(cm.AffectedPackages, aff...)
		}
	}

	classifier := &classify.Classifier{Store: store}
	class, err := classifier.Classify(cm)
	if err != nil {
		done("failed")
		return models.ScanResult{}, err
	}

	findings := buildCVEFindings(cm, class, opts)
	done("complete")

	components, pkgMap, treeStats := r.enrichCVEResult(ctx, store, opts, cm, findings)

	hash, _ := store.Hash()
	result := models.ScanResult{
		Meta: models.ScanMeta{
			Timestamp:       time.Now().UTC(),
			SnapshotVersion: store.Version(),
			SnapshotHash:    hash,
			InputPath:       cveID,
			InputHash:       inputHash(cveID),
			DurationMS:      time.Since(start).Milliseconds(),
			ComponentCount:  len(components),
			FindingCount:    len(findings),
			InputMode:       models.InputModeCVE,
			ResolvedPackage: treeStats.Root,
		},
		Summary:    report.Summarize(findings),
		Findings:   findings,
		Components: components,
		Packages:   pkgMap,
	}
	if treeStats.Total > 0 {
		result.Meta.DependencyTree = &models.DependencyTreeMeta{
			Total:      treeStats.Total,
			Direct:     treeStats.Direct,
			Transitive: treeStats.Transitive,
			Root:       treeStats.Root,
		}
	}
	result.Verbose = opts.Verbose

	if err := emitOutput(opts, result); err != nil {
		return result, err
	}
	return result, nil
}

func (r *Runner) enrichCVEResult(ctx context.Context, store *intel.Store, opts Options, cm models.CveMatch, findings []models.Finding) ([]models.Component, map[string]models.PackageContext, resolve.TreeStats) {
	pkgs := cm.NPMAffectedPackages()
	names := npmPackageNames(pkgs, findings)

	var components []models.Component
	var treeStats resolve.TreeStats
	if len(pkgs) > 0 {
		primary := pkgs[0]
		pin := representativeAffectedVersion(fixedVersionForPackage(primary, cm))
		if pin != "" {
			treeOpts := resolve.TreeOptions{
				Depth: opts.TreeDepth, IncludeDev: opts.IncludeDev, Offline: opts.Offline,
			}
			if comps, stats, err := resolve.ResolvePackageTree(ctx, primary.Name+"@"+pin, treeOpts); err == nil {
				components, treeStats = comps, stats
			}
		}
	}

	pkgMap := attachPackageContext(ctx, store, opts.Offline, findings, components, names...)
	return components, pkgMap, treeStats
}

func npmPackageNames(pkgs []models.AffectedPackage, findings []models.Finding) []string {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		if name == "" || name == "advisory-lookup" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	for _, p := range pkgs {
		add(p.Name)
	}
	for _, f := range findings {
		add(f.Component.Name)
	}
	return names
}

func fixedVersionForPackage(pkg models.AffectedPackage, cm models.CveMatch) string {
	if pkg.FixedVersion != "" {
		return pkg.FixedVersion
	}
	if len(cm.FixedVersions) > 0 {
		return cm.FixedVersions[0]
	}
	return ""
}

// representativeAffectedVersion picks a concrete npm version below the advisory
// fix line for registry tree previews in CVE-only lookups.
func representativeAffectedVersion(fixed string) string {
	v, ok := semver.Parse(fixed)
	if !ok {
		return ""
	}
	if v.Patch > 0 {
		return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch-1)
	}
	if v.Minor > 0 {
		return fmt.Sprintf("%d.%d.1", v.Major, v.Minor-1)
	}
	if v.Major > 0 {
		return fmt.Sprintf("%d.0.1", v.Major-1)
	}
	return ""
}

func buildCVEFindings(cm models.CveMatch, class models.Classification, opts Options) []models.Finding {
	pkgs := cm.NPMAffectedPackages()
	if len(pkgs) == 0 {
		return []models.Finding{buildCVEFinding(
			models.Component{Name: "advisory-lookup", Version: "n/a", Scope: models.ScopeDev, Direct: true},
			cm, class, opts,
		)}
	}
	findings := make([]models.Finding, 0, len(pkgs))
	for _, pkg := range pkgs {
		cmPkg := cm
		if pkg.FixedVersion != "" {
			cmPkg.FixedVersions = []string{pkg.FixedVersion}
		}
		version := "n/a"
		if pkg.FixedVersion != "" {
			version = "< " + pkg.FixedVersion
		}
		comp := models.Component{
			Name:    pkg.Name,
			Version: version,
			Scope:   models.ScopeDev,
			Direct:  true,
		}
		findings = append(findings, buildCVEFinding(comp, cmPkg, class, opts))
	}
	return findings
}

func buildCVEFinding(comp models.Component, cm models.CveMatch, class models.Classification, opts Options) models.Finding {
	v, reason := verdict.ComputeAdvisory(class.Priority, class.Band)
	return models.Finding{
		Component:      comp,
		CveMatch:       cm,
		Classification: class,
		Verdict:        v,
		VerdictReason:  reason,
		Briefing:       brief.Render(comp, cm, class, v, reason),
		ExposureNote:   "Advisory-only lookup (not tied to an installed dependency version)",
	}
}
