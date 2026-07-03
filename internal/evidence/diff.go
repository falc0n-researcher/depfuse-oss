package evidence

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// DiffOptions configures evidence diffing.
type DiffOptions struct {
	CVE           string
	BaselineStore *intel.Store
	CurrentStore  *intel.Store
	Since         time.Time
	SinceLabel    string
}

// Diff compares exploit evidence between baselines.
func Diff(opts DiffOptions) (*models.EvidenceDiff, error) {
	if opts.CurrentStore == nil {
		return nil, fmt.Errorf("evidence diff: current store required")
	}

	currentLabel := opts.CurrentStore.Version()
	if currentLabel == "" {
		currentLabel = "current"
	}
	baselineLabel := opts.SinceLabel
	if baselineLabel == "" && opts.BaselineStore != nil {
		baselineLabel = opts.BaselineStore.Version()
	}
	if baselineLabel == "" {
		baselineLabel = "baseline"
	}

	if !opts.Since.IsZero() {
		return diffSince(opts.CurrentStore, opts.CVE, opts.Since, baselineLabel, currentLabel)
	}
	if opts.BaselineStore == nil {
		return nil, fmt.Errorf("evidence diff: --db baseline required when --since is not set")
	}
	return diffStores(opts.BaselineStore, opts.CurrentStore, opts.CVE, baselineLabel, currentLabel)
}

func diffSince(store *intel.Store, cveID string, since time.Time, baselineLabel, currentLabel string) (*models.EvidenceDiff, error) {
	cves, err := store.CVEsWithArtifacts()
	if err != nil {
		return nil, err
	}
	if cveID != "" {
		cves = []string{strings.ToUpper(cveID)}
	}

	var changes []models.EvidenceChange
	for _, id := range cves {
		class, arts, err := ClassifyCVE(store, id)
		if err != nil {
			return nil, err
		}
		var recent []models.RawArtifact
		for _, a := range arts {
			if !a.ObservedAt.Before(since) {
				recent = append(recent, a)
			}
		}
		if len(recent) == 0 {
			continue
		}
		changes = append(changes, models.EvidenceChange{
			CVE:       id,
			Kind:      models.EvidenceAdded,
			CurrLevel: class.Priority,
			CurrHash:  Hash(class, arts),
			Summary:   fmt.Sprintf("%d new/updated artifact(s) since %s", len(recent), since.Format("2006-01-02")),
		})
	}
	sortChanges(changes)
	return &models.EvidenceDiff{
		BaselineLabel: baselineLabel,
		CurrentLabel:  currentLabel,
		Since:         since,
		Changes:       changes,
	}, nil
}

func diffStores(base, curr *intel.Store, cveID, baselineLabel, currentLabel string) (*models.EvidenceDiff, error) {
	baseCVEs, err := base.CVEsWithArtifacts()
	if err != nil {
		return nil, err
	}
	currCVEs, err := curr.CVEsWithArtifacts()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, id := range baseCVEs {
		set[id] = true
	}
	for _, id := range currCVEs {
		set[id] = true
	}
	if cveID != "" {
		set = map[string]bool{strings.ToUpper(cveID): true}
	}

	var changes []models.EvidenceChange
	for id := range set {
		baseClass, baseArts, err := ClassifyCVE(base, id)
		if err != nil {
			return nil, err
		}
		currClass, currArts, err := ClassifyCVE(curr, id)
		if err != nil {
			return nil, err
		}
		baseHash := Hash(baseClass, baseArts)
		currHash := Hash(currClass, currArts)

		switch {
		case len(baseArts) == 0 && len(currArts) > 0:
			changes = append(changes, models.EvidenceChange{
				CVE: id, Kind: models.EvidenceAdded,
				CurrLevel: currClass.Priority, CurrHash: currHash,
				Summary: fmt.Sprintf("New evidence indexed (%s)", currClass.Priority),
			})
		case len(baseArts) > 0 && len(currArts) == 0:
			changes = append(changes, models.EvidenceChange{
				CVE: id, Kind: models.EvidenceRemoved,
				PrevLevel: baseClass.Priority, PrevHash: baseHash,
				Summary: "Evidence removed from snapshot",
			})
		case baseClass.Priority != currClass.Priority:
			changes = append(changes, models.EvidenceChange{
				CVE: id, Kind: models.EvidenceLevelChange,
				PrevLevel: baseClass.Priority, CurrLevel: currClass.Priority,
				PrevHash: baseHash, CurrHash: currHash,
				Summary: fmt.Sprintf("Level %s → %s", baseClass.Priority, currClass.Priority),
			})
		case baseHash != currHash:
			changes = append(changes, models.EvidenceChange{
				CVE: id, Kind: models.EvidenceHashChange,
				PrevLevel: baseClass.Priority, CurrLevel: currClass.Priority,
				PrevHash: baseHash, CurrHash: currHash,
				Summary: "Evidence hash changed (signals or artifacts moved)",
			})
		}
	}
	sortChanges(changes)
	return &models.EvidenceDiff{
		BaselineLabel: baselineLabel,
		CurrentLabel:  currentLabel,
		Changes:       changes,
	}, nil
}

func sortChanges(changes []models.EvidenceChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].CurrLevel != changes[j].CurrLevel {
			return changes[i].CurrLevel < changes[j].CurrLevel
		}
		return changes[i].CVE < changes[j].CVE
	})
}
