package models

import "time"

// EvidenceEvent is one dated entry in an exploit-evidence timeline.
type EvidenceEvent struct {
	At      time.Time `json:"at"`
	Source  Source    `json:"source"`
	Title   string    `json:"title"`
	URL     string    `json:"url,omitempty"`
	Summary string    `json:"summary"`
}

// EvidenceState captures the current exploit-evidence picture for a CVE.
type EvidenceState struct {
	CVE       string          `json:"cve"`
	Level     Priority        `json:"level"`
	Signals   Signals         `json:"signals"`
	Hash      string          `json:"evidenceHash"`
	ChangedAt time.Time       `json:"evidenceChangedAt"`
	Events    []EvidenceEvent `json:"events"`
}

// DecisionImpact describes how a prior scan decision relates to current evidence.
type DecisionImpact struct {
	PreviousLevel  Priority  `json:"previousLevel,omitempty"`
	PreviousHash   string    `json:"previousEvidenceHash,omitempty"`
	PreviousScanAt time.Time `json:"previousScanAt,omitempty"`
	ReopenRequired bool      `json:"reopenRequired"`
	Summary        string    `json:"summary"`
}

// EvidenceTimeline is the Milestone 1 output for cve --timeline.
type EvidenceTimeline struct {
	CVE            string          `json:"cve"`
	State          EvidenceState   `json:"state"`
	DecisionImpact *DecisionImpact `json:"decisionImpact,omitempty"`
}

// EvidenceChangeKind tags a row in an evidence diff.
type EvidenceChangeKind string

const (
	EvidenceAdded       EvidenceChangeKind = "added"
	EvidenceRemoved     EvidenceChangeKind = "removed"
	EvidenceLevelChange EvidenceChangeKind = "level_change"
	EvidenceHashChange  EvidenceChangeKind = "hash_change"
)

// EvidenceChange is one CVE-level delta between two intel snapshots.
type EvidenceChange struct {
	CVE       string             `json:"cve"`
	Kind      EvidenceChangeKind `json:"kind"`
	PrevLevel Priority           `json:"prevLevel,omitempty"`
	CurrLevel Priority           `json:"currLevel,omitempty"`
	PrevHash  string             `json:"prevEvidenceHash,omitempty"`
	CurrHash  string             `json:"currEvidenceHash,omitempty"`
	Summary   string             `json:"summary"`
}

// EvidenceDiff summarizes exploit-evidence movement between baselines.
type EvidenceDiff struct {
	BaselineLabel string           `json:"baselineLabel"`
	CurrentLabel  string           `json:"currentLabel"`
	Since         time.Time        `json:"since,omitempty"`
	Changes       []EvidenceChange `json:"changes"`
}

// PackageEvidenceRow is evidence-focused output for package --evidence.
type PackageEvidenceRow struct {
	Package      string          `json:"package"`
	CVE          string          `json:"cve"`
	Level        Priority        `json:"level"`
	Signals      Signals         `json:"signals"`
	EvidenceHash string          `json:"evidenceHash"`
	Events       []EvidenceEvent `json:"events"`
	Verdict      Verdict         `json:"verdict"`
}
