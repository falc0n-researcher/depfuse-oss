package evidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/history"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// DecisionImpactFromHistory compares current evidence against the last scan_history row for a CVE lookup.
func DecisionImpactFromHistory(hist *history.Store, inputHash, cveID string, curr models.Classification, currHash string) *models.DecisionImpact {
	if hist == nil || hist.Intel == nil {
		return nil
	}
	prevSnaps, prevAt, err := hist.LoadPrevious(inputHash)
	if err != nil || len(prevSnaps) == 0 {
		return nil
	}

	var prev *models.HistorySnapshot
	for i := range prevSnaps {
		if strings.EqualFold(prevSnaps[i].CVEID, cveID) {
			prev = &prevSnaps[i]
			break
		}
	}
	if prev == nil {
		return &models.DecisionImpact{
			PreviousScanAt: prevAt,
			Summary:        "No prior record for this CVE in last scan",
		}
	}

	reopen := curr.Priority < prev.Level
	summary := fmt.Sprintf("Previous scan at level=%s; current level=%s", prev.Level, curr.Priority)
	if reopen {
		summary = fmt.Sprintf("Reopen required: level changed %s → %s", prev.Level, curr.Priority)
	} else if currHash != "" {
		summary = fmt.Sprintf("Previous scan at level=%s (unchanged); evidence hash may differ", prev.Level)
	}

	return &models.DecisionImpact{
		PreviousLevel:  prev.Level,
		PreviousScanAt: prevAt,
		ReopenRequired: reopen,
		Summary:        summary,
	}
}

// SinceFromStore resolves a --since filter against intel.db metadata.
func SinceFromStore(store *intel.Store, since string) (time.Time, string, error) {
	since = strings.TrimSpace(since)
	if since == "" {
		return time.Time{}, "", nil
	}
	switch strings.ToLower(since) {
	case "last-db", "last-collect":
		prev, err := store.PreviousCollectedAt()
		if err != nil {
			return time.Time{}, "", err
		}
		if prev.IsZero() {
			return time.Time{}, "", fmt.Errorf("no previous collect timestamp in intel.db — run collect twice or use --since YYYY-MM-DD")
		}
		return prev, prev.Format(time.RFC3339), nil
	default:
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
			if t, err := time.Parse(layout, since); err == nil {
				return t.UTC(), since, nil
			}
		}
		return time.Time{}, "", fmt.Errorf("invalid --since value %q (use YYYY-MM-DD, RFC3339, or last-db)", since)
	}
}
