package history

import "github.com/falc0n-researcher/depfuse-oss/pkg/models"

func ToSnapshot(f models.Finding) models.HistorySnapshot {
	cveID := f.CveMatch.CVEID
	if cveID == "" {
		cveID = f.CveMatch.AdvisoryID()
	}
	return models.HistorySnapshot{
		Key:     FindingKey(f.Component, f.CveMatch),
		CVEID:   cveID,
		Package: f.Component.Name + "@" + f.Component.Version,
		Level:   f.Classification.Priority,
		Verdict: f.Verdict,
		EPSS:    f.Classification.Signals.EPSS,
	}
}
