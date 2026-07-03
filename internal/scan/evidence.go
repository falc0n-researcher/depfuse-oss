package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/internal/evidence"
	"github.com/falc0n-researcher/depfuse-oss/internal/history"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/verdict"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// RunCVETimeline prints the dated evidence timeline for a CVE.
func (r *Runner) RunCVETimeline(ctx context.Context, cveID string, opts Options) error {
	store, err := r.openStore(ctx, opts)
	if err != nil {
		return err
	}
	defer store.Close()

	hist := &history.Store{Intel: store}
	inputKey := inputHash(cveID)

	class, arts, err := evidence.ClassifyCVE(store, cveID)
	if err != nil {
		return err
	}
	hash := evidence.Hash(class, arts)
	impact := evidence.DecisionImpactFromHistory(hist, inputKey, cveID, class, hash)

	tl, err := evidence.BuildTimeline(store, cveID, impact)
	if err != nil {
		return err
	}
	if err := emitEvidenceTimeline(opts, tl); err != nil {
		return err
	}

	if !opts.NoHistory {
		v, _ := verdict.ComputeAdvisory(class.Priority, class.Band)
		snap := models.HistorySnapshot{
			Key: inputKey + ":" + cveID, CVEID: cveID,
			Package: "advisory-lookup@n/a", Level: class.Priority,
			Verdict: v, EPSS: class.Signals.EPSS,
		}
		_ = hist.Save(inputKey, store.Version(), time.Now().UTC(), []models.HistorySnapshot{snap})
	}
	return nil
}

// EvidenceDiffOptions configures evidence diff runs.
type EvidenceDiffOptions struct {
	CVE          string
	DBPath       string
	BaselineDB   string
	SinceSpec    string
	OutputFormat string
}

// RunEvidenceDiff compares exploit evidence between intel snapshots.
func (r *Runner) RunEvidenceDiff(ctx context.Context, opts EvidenceDiffOptions) error {
	curr, err := r.openStoreAt(ctx, opts.DBPath)
	if err != nil {
		return err
	}
	defer curr.Close()

	var base *intel.Store
	if opts.BaselineDB != "" {
		base, err = intel.Open(opts.BaselineDB)
		if err != nil {
			return fmt.Errorf("open baseline db: %w", err)
		}
		defer base.Close()
	}

	since, err := parseSince(curr, opts)
	if err != nil {
		return err
	}
	sinceLabel := ""
	if !since.IsZero() {
		sinceLabel = opts.SinceSpec
	}

	diff, err := evidence.Diff(evidence.DiffOptions{
		CVE:           opts.CVE,
		BaselineStore: base,
		CurrentStore:  curr,
		Since:         since,
		SinceLabel:    sinceLabel,
	})
	if err != nil {
		return err
	}
	return emitEvidenceDiff(opts.OutputFormat, diff)
}

func parseSince(curr *intel.Store, opts EvidenceDiffOptions) (time.Time, error) {
	if opts.SinceSpec == "" {
		return time.Time{}, nil
	}
	t, _, err := evidence.SinceFromStore(curr, opts.SinceSpec)
	return t, err
}

func (r *Runner) openStoreAt(ctx context.Context, path string) (*intel.Store, error) {
	if path == "" {
		return r.openStore(ctx, Options{})
	}
	return intel.Open(path)
}

func emitEvidenceTimeline(opts Options, tl *models.EvidenceTimeline) error {
	switch opts.Format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(tl)
	default:
		ui.RenderEvidenceTimeline(os.Stdout, tl)
		return nil
	}
}

func emitEvidenceDiff(format string, diff *models.EvidenceDiff) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(diff)
	default:
		ui.RenderEvidenceDiff(os.Stdout, diff)
		return nil
	}
}

// RunPackageEvidence runs a package lookup with evidence-focused output.
func (r *Runner) RunPackageEvidence(ctx context.Context, pkg string, opts Options) (int, error) {
	opts.Package = pkg
	opts.SkipEmit = true

	store, err := r.openStore(ctx, opts)
	if err != nil {
		return 1, err
	}
	defer store.Close()

	saved := r.Store
	r.Store = store
	defer func() { r.Store = saved }()

	result, code, err := r.Run(ctx, opts)
	if err != nil {
		return code, err
	}

	rows := packageEvidenceRows(store, result.Findings)
	if opts.Format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		payload := map[string]any{"package": pkg, "findings": rows}
		if result.Meta.PackageContext != nil {
			payload["packageContext"] = result.Meta.PackageContext
		}
		if len(result.Packages) > 0 {
			payload["packages"] = result.Packages
		}
		if err := enc.Encode(payload); err != nil {
			return code, err
		}
		return code, nil
	}
	if result.Meta.PackageContext != nil {
		ui.RenderPackageContextHeader(os.Stdout, result.Meta.PackageContext)
	}
	ui.RenderPackageEvidence(os.Stdout, pkg, rows)
	return code, nil
}

func packageEvidenceRows(store *intel.Store, findings []models.Finding) []models.PackageEvidenceRow {
	out := make([]models.PackageEvidenceRow, 0, len(findings))
	for _, f := range findings {
		ids := append([]string{f.CveMatch.CVEID, f.CveMatch.OSVID, f.CveMatch.GHSAID}, f.CveMatch.Aliases...)
		arts, _ := store.ArtifactsForAnyID(ids...)
		out = append(out, models.PackageEvidenceRow{
			Package:      fmt.Sprintf("%s@%s", f.Component.Name, f.Component.Version),
			CVE:          f.CveMatch.CVEID,
			Level:        f.Classification.Priority,
			Signals:      f.Classification.Signals,
			EvidenceHash: evidence.Hash(f.Classification, arts),
			Events:       evidence.EventsFromArtifacts(arts),
			Verdict:      f.Verdict,
		})
	}
	return out
}
