package history

import (
	"fmt"
	"math"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const epssShiftThreshold = 0.05

// ComputeDelta diffs current findings against a prior history snapshot.
func ComputeDelta(prev []models.HistorySnapshot, curr []models.Finding, prevAt time.Time) models.ScanDelta {
	prevMap := make(map[string]models.HistorySnapshot, len(prev))
	for _, p := range prev {
		prevMap[p.Key] = p
	}
	seen := make(map[string]bool, len(curr))
	var d models.ScanDelta
	d.PreviousScanAt = prevAt

	for _, f := range curr {
		key := FindingKey(f.Component, f.CveMatch)
		seen[key] = true
		snap := ToSnapshot(f)
		p, ok := prevMap[key]
		if !ok {
			d.NewFindings = append(d.NewFindings, models.FindingDelta{
				Key: key, Kind: models.DeltaNew,
				CVEID: snap.CVEID, Package: snap.Package,
				CurrLevel: snap.Level, CurrVerdict: snap.Verdict, CurrEPSS: snap.EPSS,
				Summary: "new finding",
			})
			continue
		}
		switch {
		case snap.Level < p.Level:
			d.Escalated = append(d.Escalated, models.FindingDelta{
				Key: key, Kind: models.DeltaLevelUp,
				CVEID: snap.CVEID, Package: snap.Package,
				PrevLevel: p.Level, CurrLevel: snap.Level,
				PrevVerdict: p.Verdict, CurrVerdict: snap.Verdict,
				PrevEPSS: p.EPSS, CurrEPSS: snap.EPSS,
				Summary: fmt.Sprintf("%s → %s", p.Level, snap.Level),
			})
		case snap.Level > p.Level:
			d.Deescalated = append(d.Deescalated, models.FindingDelta{
				Key: key, Kind: models.DeltaLevelDown,
				CVEID: snap.CVEID, Package: snap.Package,
				PrevLevel: p.Level, CurrLevel: snap.Level,
				PrevVerdict: p.Verdict, CurrVerdict: snap.Verdict,
				PrevEPSS: p.EPSS, CurrEPSS: snap.EPSS,
				Summary: fmt.Sprintf("%s → %s", p.Level, snap.Level),
			})
		case math.Abs(snap.EPSS-p.EPSS) >= epssShiftThreshold:
			d.EPSSShifts = append(d.EPSSShifts, models.FindingDelta{
				Key: key, Kind: models.DeltaEPSSShift,
				CVEID: snap.CVEID, Package: snap.Package,
				PrevLevel: p.Level, CurrLevel: snap.Level,
				PrevEPSS: p.EPSS, CurrEPSS: snap.EPSS,
				Summary: fmt.Sprintf("EPSS %.2f → %.2f", p.EPSS, snap.EPSS),
			})
		}
	}

	for key, p := range prevMap {
		if seen[key] {
			continue
		}
		d.Removed = append(d.Removed, models.FindingDelta{
			Key: key, Kind: models.DeltaRemoved,
			CVEID: p.CVEID, Package: p.Package,
			PrevLevel: p.Level, PrevVerdict: p.Verdict, PrevEPSS: p.EPSS,
			Summary: "no longer matched",
		})
	}
	return d
}
