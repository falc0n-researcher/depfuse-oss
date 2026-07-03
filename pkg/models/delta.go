package models

import "time"

// DeltaKind classifies a finding transition between scans.
type DeltaKind string

const (
	DeltaLevelUp   DeltaKind = "level_up"
	DeltaLevelDown DeltaKind = "level_down"
	DeltaUnchanged DeltaKind = "unchanged"
	DeltaNew       DeltaKind = "new_finding"
	DeltaRemoved   DeltaKind = "removed"
	DeltaEPSSShift DeltaKind = "epss_shift"
)

// FindingDelta is one row in a scan comparison.
type FindingDelta struct {
	Key         string    `json:"key"`
	Kind        DeltaKind `json:"kind"`
	CVEID       string    `json:"cveId"`
	Package     string    `json:"package"`
	PrevLevel   Priority  `json:"prevLevel,omitempty"`
	CurrLevel   Priority  `json:"currLevel,omitempty"`
	PrevEPSS    float64   `json:"prevEpss,omitempty"`
	CurrEPSS    float64   `json:"currEpss,omitempty"`
	PrevVerdict Verdict   `json:"prevVerdict,omitempty"`
	CurrVerdict Verdict   `json:"currVerdict,omitempty"`
	Summary     string    `json:"summary"`
}

// ScanDelta aggregates transitions since the previous scan.
type ScanDelta struct {
	PreviousScanAt time.Time      `json:"previousScanAt"`
	PreviousHash   string         `json:"previousSnapshotHash,omitempty"`
	Escalated      []FindingDelta `json:"escalated,omitempty"`
	Deescalated    []FindingDelta `json:"deescalated,omitempty"`
	EPSSShifts     []FindingDelta `json:"epssShifts,omitempty"`
	NewFindings    []FindingDelta `json:"newFindings,omitempty"`
	Removed        []FindingDelta `json:"removed,omitempty"`
}

// HasChanges reports whether any transition bucket is non-empty.
func (d *ScanDelta) HasChanges() bool {
	if d == nil {
		return false
	}
	return len(d.Escalated)+len(d.Deescalated)+len(d.EPSSShifts)+len(d.NewFindings)+len(d.Removed) > 0
}
