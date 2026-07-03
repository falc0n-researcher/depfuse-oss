package scan

import (
	"context"
	"fmt"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// RunInventory resolves all components and optionally matches CVE findings.
// It does not apply decision memory, history, or emit output — that is left
// to the caller (the inventory command).
func (r *Runner) RunInventory(ctx context.Context, opts Options) ([]models.Component, []models.Finding, error) {
	prog := ui.NewProgress(osStderr(), opts.Quiet)

	done := prog.Step("Intelligence")
	store, err := r.openStore(ctx, opts)
	if err != nil {
		done("failed")
		return nil, nil, err
	}
	done("ready")
	defer store.Close()

	if opts.Offline && !store.HasOSVNPM() && !store.HasOSVCache() {
		fmt.Fprintf(osStderr(), "warning: offline mode but intel.db has no advisory data — CVE annotations will be empty\n")
	}

	done = prog.Step("Resolve dependencies")
	_, components, _, err := r.resolveInput(ctx, opts)
	if err != nil {
		done("failed")
		return nil, nil, err
	}
	done(fmt.Sprintf("%d packages", len(components)))

	done = prog.Step("Match vulnerabilities")
	componentMatches, _, err := r.matchCVEs(ctx, store, opts, components)
	if err != nil {
		done("failed")
		return nil, nil, err
	}
	matchCount := 0
	for _, cm := range componentMatches {
		matchCount += len(cm.Matches)
	}
	done(fmt.Sprintf("%d CVE matches", matchCount))

	done = prog.Step("Classify")
	findings, err := r.classifyAndVerdict(store, componentMatches, opts)
	if err != nil {
		done("failed")
		return nil, nil, err
	}
	done(fmt.Sprintf("%d findings", len(findings)))

	return components, findings, nil
}
