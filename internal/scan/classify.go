package scan

import (
	"fmt"
	"os"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/brief"
	"github.com/falc0n-researcher/depfuse-oss/internal/classify"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/match"
	"github.com/falc0n-researcher/depfuse-oss/internal/remediation"
	"github.com/falc0n-researcher/depfuse-oss/internal/report"
	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/internal/verdict"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func (r *Runner) classifyAndVerdict(store *intel.Store, componentMatches []match.ComponentMatch, opts Options) ([]models.Finding, error) {
	classifier := &classify.Classifier{Store: store}
	var findings []models.Finding

	for _, cm := range componentMatches {
		for _, cve := range cm.Matches {
			advisoryID := cve.AdvisoryID()
			if advisoryID == "" {
				continue
			}
			if cve.CVEID == "" {
				cve.CVEID = advisoryID
			}
			class, err := classifier.Classify(cve)
			if err != nil {
				return nil, fmt.Errorf("classify %s: %w", advisoryID, err)
			}
			v, reason := verdict.Compute(cm.Component, class.Priority, class.Band)
			b := brief.Render(cm.Component, cve, class, v, reason)
			recs := verdict.BuildReceipts(cm.Component, cve, class)
			if class.Priority <= models.PriorityP2 && !brief.ValidateGrounding(class, b) {
				fmt.Fprintf(osStderr(), "warning: briefing for %s lacks grounded evidence\n", advisoryID)
			}
			rem := remediation.Assess(cm.Component.Version, fixedVersionsFor(cve, cm.Component.Name))
			findings = append(findings, models.Finding{
				Component:      cm.Component,
				CveMatch:       cve,
				Classification: class,
				Remediation:    &rem,
				Verdict:        v,
				VerdictReason:  reason,
				Receipts:       recs,
				Briefing:       b,
				ExposureNote:   report.ExposureNote(cm.Component),
			})
		}
	}

	report.Rank(findings)
	return findings, nil
}

func fixedVersionsFor(cve models.CveMatch, pkg string) []string {
	if len(cve.FixedVersions) > 0 {
		return cve.FixedVersions
	}
	var fixes []string
	for _, p := range cve.NPMAffectedPackages() {
		if p.Name == pkg && p.FixedVersion != "" {
			fixes = append(fixes, p.FixedVersion)
		}
	}
	return fixes
}

func buildResult(store *intel.Store, root string, opts Options, components []models.Component, active, suppressed, accepted []models.Finding, start time.Time, osvStats match.Stats, tree resolve.TreeStats) models.ScanResult {
	hash, _ := store.Hash()
	reopened := 0
	for _, f := range active {
		if f.Reopened {
			reopened++
		}
	}
	meta := models.ScanMeta{
		Timestamp:       time.Now().UTC(),
		SnapshotVersion: store.Version(),
		SnapshotHash:    hash,
		InputPath:       firstNonEmpty(root, opts.RepoURL, opts.Package),
		InputHash:       inputHash(root, opts.RepoURL, opts.Package),
		DurationMS:      time.Since(start).Milliseconds(),
		ComponentCount:  len(components),
		FindingCount:    len(active),
		OSVCacheHits:    osvStats.OSVCacheHits,
		OSVQueries:      osvStats.OSVQueries,
		OSVChunks:       osvStats.OSVChunks,
		SuppressedCount: len(suppressed),
		AcceptedCount:   len(accepted),
		ReopenedCount:   reopened,
	}
	if tree.Total > 0 && (tree.Transitive > 0 || tree.Root != "") {
		meta.DependencyTree = &models.DependencyTreeMeta{
			Total: tree.Total, Direct: tree.Direct, Transitive: tree.Transitive, Root: tree.Root,
		}
	}
	if opts.Package == "" && opts.RepoURL == "" {
		meta.Coverage = resolve.ComputeCoverage(root, components, tree)
	}
	return models.ScanResult{
		Meta:       meta,
		Summary:    report.Summarize(active),
		Findings:   active,
		Suppressed: suppressed,
		Accepted:   accepted,
		Components: components,
	}
}

func scanExitCode(opts Options, result models.ScanResult, active, suppressed []models.Finding) int {
	// Incomplete lockfile coverage always fails — a partial scan must not look like success.
	if cov := result.Meta.Coverage; cov != nil && cov.IsIncomplete() {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			fmt.Fprintf(os.Stdout, "::error title=Depfuse scan incomplete::%s\n", cov.Message)
		}
		return 1
	}
	if !opts.CI {
		return 0
	}
	failTiers := verdict.ParseFailTiers(opts.FailOn)
	failures := report.CIFailures(active, failTiers)
	if len(failures) == 0 {
		if os.Getenv("GITHUB_ACTIONS") == "true" && len(suppressed) > 0 {
			report.EmitGitHubSuppressionWarnings(os.Stdout, suppressed)
		}
		return 0
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		report.EmitGitHubAnnotations(os.Stdout, failures)
		if len(suppressed) > 0 {
			report.EmitGitHubSuppressionWarnings(os.Stdout, suppressed)
		}
	}
	return 1
}
