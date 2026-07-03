package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/classify"
	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/internal/decisions"
	"github.com/falc0n-researcher/depfuse-oss/internal/evidence"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// DecideOptions configures depfuse decide.
type DecideOptions struct {
	CVE      string
	Package  string
	Version  string
	Decision models.DecisionKind
	Reason   string
	Path     string
	DBPath   string
	Offline  bool
}

// RunDecide records a durable decision bound to current exploit evidence.
func (r *Runner) RunDecide(ctx context.Context, opts DecideOptions) (models.StoredDecision, error) {
	if strings.TrimSpace(opts.CVE) == "" {
		return models.StoredDecision{}, fmt.Errorf("CVE id required")
	}
	if strings.TrimSpace(opts.Reason) == "" {
		return models.StoredDecision{}, fmt.Errorf("--reason is required")
	}
	switch opts.Decision {
	case models.DecisionAcceptedRisk, models.DecisionBlocked, models.DecisionNotApplicable:
	default:
		return models.StoredDecision{}, fmt.Errorf("decision must be accepted-risk, blocked, or not-applicable")
	}

	root := opts.Path
	if root == "" {
		root = "."
	}

	store, err := r.openStore(ctx, Options{DBPath: opts.DBPath, Offline: opts.Offline})
	if err != nil {
		return models.StoredDecision{}, err
	}
	defer store.Close()

	cm := models.CveMatch{CVEID: strings.ToUpper(strings.TrimSpace(opts.CVE))}
	_ = intel.EnrichCveMatch(ctx, store, &cm, opts.Offline)
	classifier := &classify.Classifier{Store: store}
	class, err := classifier.Classify(cm)
	if err != nil {
		return models.StoredDecision{}, err
	}
	arts, _ := store.ArtifactsForAnyID(cm.CVEID)

	d := models.StoredDecision{
		CVE:                     cm.CVEID,
		Package:                 strings.TrimSpace(opts.Package),
		Version:                 strings.TrimSpace(opts.Version),
		Decision:                opts.Decision,
		Reason:                  strings.TrimSpace(opts.Reason),
		DecidedAt:               time.Now().UTC(),
		DecidedWhenLevel:        class.Priority,
		DecidedWhenEvidenceHash: evidence.Hash(class, arts),
		DecidedWhenSignals:      class.Signals,
		ReopenPolicy:            models.DefaultReopenPolicy,
	}
	decisions.Normalize(&d)

	file, err := decisions.Load(root)
	if err != nil {
		return models.StoredDecision{}, err
	}
	file.Add(d)
	if err := decisions.Save(file); err != nil {
		return models.StoredDecision{}, err
	}
	return d, nil
}

// WatchOptions configures depfuse watch.
type WatchOptions struct {
	Options
	BaselineDB string
	SinceSpec  string
}

// RunWatch surfaces what needs attention vs what stays silent under decision memory.
func (r *Runner) RunWatch(ctx context.Context, opts WatchOptions) (models.WatchResult, error) {
	scanOpts := opts.Options
	scanOpts.Delta = true
	scanOpts.SkipEmit = true

	result, _, err := r.Run(ctx, scanOpts)
	if err != nil {
		return models.WatchResult{}, err
	}

	wr := models.WatchResult{InputPath: result.Meta.InputPath}
	if result.Delta != nil {
		wr.PreviousScanAt = result.Delta.PreviousScanAt
		wr.Escalated = result.Delta.Escalated
		wr.EPSSShifts = result.Delta.EPSSShifts
	}

	decFile, _ := decisions.Load(firstNonEmpty(scanOpts.Path, "."))
	for _, f := range result.Findings {
		item := models.WatchItem{
			CVE:     f.CveMatch.CVEID,
			Package: f.Component.Name + "@" + f.Component.Version,
			Level:   f.Classification.Priority,
		}
		if f.Reopened {
			item.ReopenSummary = f.ReopenSummary
			if d, ok := decFile.Match(f); ok {
				item.Decision = d.Decision
				item.Reason = d.Reason
			}
			wr.Reopened = append(wr.Reopened, item)
			continue
		}
	}
	for _, f := range result.Accepted {
		item := models.WatchItem{
			CVE: f.CveMatch.CVEID, Package: f.Component.Name + "@" + f.Component.Version,
			Level: f.Classification.Priority, Silent: true, Reason: f.DecisionReason,
			Decision: models.DecisionAcceptedRisk,
		}
		if d, ok := decFile.Match(f); ok {
			item.Decision = d.Decision
			if item.Reason == "" {
				item.Reason = d.Reason
			}
		}
		wr.Silent = append(wr.Silent, item)
	}

	wr.Digest = buildWatchDigest(wr)

	store, err := r.openStore(ctx, scanOpts)
	if err == nil {
		defer store.Close()
		if opts.SinceSpec != "" {
			since, _, sinceErr := evidence.SinceFromStore(store, opts.SinceSpec)
			if sinceErr == nil && !since.IsZero() {
				diff, err := evidence.Diff(evidence.DiffOptions{
					CurrentStore: store, Since: since, SinceLabel: opts.SinceSpec,
				})
				if err == nil {
					wr.IntelChanges = diff.Changes
				}
			}
		} else if opts.BaselineDB != "" {
			base, err := intel.Open(opts.BaselineDB)
			if err == nil {
				defer base.Close()
				diff, err := evidence.Diff(evidence.DiffOptions{
					BaselineStore: base, CurrentStore: store,
				})
				if err == nil {
					wr.IntelChanges = diff.Changes
				}
			}
		}
	}

	if err := emitWatch(scanOpts.Format, wr); err != nil {
		return wr, err
	}
	return wr, nil
}

func emitWatch(format string, wr models.WatchResult) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(wr)
	case "markdown", "md":
		ui.RenderWatchMarkdown(os.Stdout, wr)
		return nil
	default:
		ui.RenderWatch(os.Stdout, wr)
		return nil
	}
}

func buildWatchDigest(wr models.WatchResult) models.WatchDigest {
	d := models.WatchDigest{
		EscalatedCount: len(wr.Escalated),
		ReopenedCount:  len(wr.Reopened),
		EPSSShiftCount: len(wr.EPSSShifts),
		SilentCount:    len(wr.Silent),
	}
	parts := []string{}
	if d.EscalatedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d escalated since last scan", d.EscalatedCount))
	}
	if d.ReopenedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d decisions reopened", d.ReopenedCount))
	}
	if d.EPSSShiftCount > 0 {
		parts = append(parts, fmt.Sprintf("%d EPSS shifts", d.EPSSShiftCount))
	}
	if len(parts) == 0 {
		d.Summary = "No reopens or escalations — accepted decisions hold."
	} else {
		d.Summary = strings.Join(parts, " · ")
	}
	return d
}

// ListDecisions returns decisions from root/.depfuse/decisions.yaml.
func ListDecisions(root string) (decisions.File, error) {
	if root == "" {
		root = "."
	}
	return decisions.Load(root)
}

// ExportDecisions writes decisions as yaml or json to stdout.
func ExportDecisions(root, format string) error {
	file, err := ListDecisions(root)
	if err != nil {
		return err
	}
	doc := models.DecisionFile{Decisions: file.Decisions}
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	case "openvex":
		return fmt.Errorf("OpenVEX export is planned for v0.2 — use --format yaml or json")
	default:
		data, err := decisions.MarshalYAML(doc)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	}
}
