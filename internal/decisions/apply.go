package decisions

import (
	"fmt"

	"github.com/falc0n-researcher/depfuse-oss/internal/evidence"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// ApplyOutcome describes how a stored decision affected one finding.
type ApplyOutcome struct {
	Finding       models.Finding
	Accepted      bool
	Reopened      bool
	Decision      models.StoredDecision
	ReopenSummary string
}

// Apply evaluates stored decisions against findings. Accepted-risk decisions
// suppress output unless reopened; blocked decisions always surface.
func Apply(store *intel.Store, findings []models.Finding, file File) (active, accepted []models.Finding, outcomes []ApplyOutcome) {
	for _, f := range findings {
		d, ok := file.Match(f)
		if !ok {
			active = append(active, f)
			continue
		}

		reopen, summary := ShouldReopen(d, f.Classification)
		out := ApplyOutcome{Finding: f, Decision: d, ReopenSummary: summary}

		switch d.Decision {
		case models.DecisionAcceptedRisk, models.DecisionNotApplicable:
			if reopen {
				f.Reopened = true
				f.DecisionReason = d.Reason
				f.ReopenSummary = summary
				f.VerdictReason = fmt.Sprintf("REOPEN: %s (was: %s)", summary, d.Reason)
				out.Reopened = true
				active = append(active, f)
			} else {
				f.AcceptedRisk = true
				f.DecisionReason = d.Reason
				f.Suppressed = true
				f.SuppressionReason = fmt.Sprintf("accepted-risk: %s", d.Reason)
				out.Accepted = true
				accepted = append(accepted, f)
			}
		case models.DecisionBlocked:
			f.DecisionReason = d.Reason
			if reopen {
				f.Reopened = true
				f.ReopenSummary = summary
			}
			active = append(active, f)
		default:
			active = append(active, f)
		}
		outcomes = append(outcomes, out)
		_ = store
	}
	return active, accepted, outcomes
}

// EvidenceHashForFinding computes the current evidence hash for a finding.
func EvidenceHashForFinding(store *intel.Store, f models.Finding) string {
	if store == nil {
		return evidence.Hash(f.Classification, nil)
	}
	ids := append([]string{f.CveMatch.CVEID, f.CveMatch.OSVID, f.CveMatch.GHSAID}, f.CveMatch.Aliases...)
	arts, _ := store.ArtifactsForAnyID(ids...)
	return evidence.Hash(f.Classification, arts)
}
