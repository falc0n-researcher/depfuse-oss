package models

import "time"

// DecisionKind is a durable triage outcome stored in .depfuse/decisions.yaml.
type DecisionKind string

const (
	DecisionAcceptedRisk  DecisionKind = "accepted-risk"
	DecisionBlocked       DecisionKind = "blocked"
	DecisionNotApplicable DecisionKind = "not-applicable"
)

// ReopenTrigger names a policy rule that can wake a stored decision.
type ReopenTrigger string

const (
	ReopenLevelIncrease        ReopenTrigger = "level_increase"
	ReopenKEVAdded             ReopenTrigger = "kev_added"
	ReopenMetasploitAdded      ReopenTrigger = "metasploit_added"
	ReopenNucleiAdded          ReopenTrigger = "nuclei_added"
	ReopenExploitArtifactAdded ReopenTrigger = "exploit_artifact_added"
	ReopenEPSSThreshold        ReopenTrigger = "epss_threshold"
)

// DefaultReopenPolicy is applied when a stored decision omits reopen_policy.
var DefaultReopenPolicy = []ReopenTrigger{
	ReopenLevelIncrease,
	ReopenKEVAdded,
	ReopenMetasploitAdded,
	ReopenExploitArtifactAdded,
	ReopenEPSSThreshold,
}

// StoredDecision is one row in the local decision file.
type StoredDecision struct {
	CVE                     string          `yaml:"cve" json:"cve"`
	Package                 string          `yaml:"package,omitempty" json:"package,omitempty"`
	Version                 string          `yaml:"version,omitempty" json:"version,omitempty"`
	Decision                DecisionKind    `yaml:"decision" json:"decision"`
	Reason                  string          `yaml:"reason" json:"reason"`
	DecidedAt               time.Time       `yaml:"decided_at" json:"decidedAt"`
	DecidedWhenLevel        Priority        `yaml:"decided_when_level" json:"decidedWhenLevel"`
	DecidedWhenEvidenceHash string          `yaml:"decided_when_evidence_hash" json:"decidedWhenEvidenceHash"`
	DecidedWhenSignals      Signals         `yaml:"decided_when_signals,omitempty" json:"decidedWhenSignals,omitempty"`
	ReopenPolicy            []ReopenTrigger `yaml:"reopen_policy,omitempty" json:"reopenPolicy,omitempty"`
}

// DecisionFile is the on-disk decision corpus.
type DecisionFile struct {
	Decisions []StoredDecision `yaml:"decisions" json:"decisions"`
}

// DecisionExplain is the `depfuse decisions explain` output for one stored
// decision: what was decided, the evidence tier at decision time vs the
// current re-classified tier, and whether it would reopen right now.
type DecisionExplain struct {
	Decision     StoredDecision `json:"decision"`
	CurrentLevel Priority       `json:"currentLevel"`
	WouldReopen  bool           `json:"wouldReopen"`
	ReopenReason string         `json:"reopenReason,omitempty"`
}

// WatchItem summarizes one finding under decision memory during watch.
type WatchItem struct {
	CVE           string       `json:"cve"`
	Package       string       `json:"package"`
	Level         Priority     `json:"level"`
	Decision      DecisionKind `json:"decision"`
	Reason        string       `json:"reason,omitempty"`
	ReopenSummary string       `json:"reopenSummary,omitempty"`
	Silent        bool         `json:"silent"`
}

// WatchResult is the unified watch command output.
type WatchResult struct {
	InputPath      string           `json:"inputPath,omitempty"`
	PreviousScanAt time.Time        `json:"previousScanAt,omitempty"`
	Digest         WatchDigest      `json:"digest"`
	Reopened       []WatchItem      `json:"reopened,omitempty"`
	Silent         []WatchItem      `json:"silent,omitempty"`
	Escalated      []FindingDelta   `json:"escalated,omitempty"`
	EPSSShifts     []FindingDelta   `json:"epssShifts,omitempty"`
	IntelChanges   []EvidenceChange `json:"intelChanges,omitempty"`
}

// WatchDigest summarizes watch output for CI and markdown reports.
type WatchDigest struct {
	EscalatedCount int    `json:"escalatedCount"`
	ReopenedCount  int    `json:"reopenedCount"`
	EPSSShiftCount int    `json:"epssShiftCount"`
	SilentCount    int    `json:"silentCount"`
	Summary        string `json:"summary"`
}

func (w *WatchResult) HasAttention() bool {
	if w == nil {
		return false
	}
	return len(w.Reopened)+len(w.Escalated)+len(w.IntelChanges) > 0
}

// ReopenPolicyLabels returns human-readable reopen triggers for reports and CLI.
func ReopenPolicyLabels() []string {
	labels := make([]string, 0, len(DefaultReopenPolicy))
	for _, t := range DefaultReopenPolicy {
		switch t {
		case ReopenLevelIncrease:
			labels = append(labels, "priority increases")
		case ReopenKEVAdded:
			labels = append(labels, "KEV listing added")
		case ReopenMetasploitAdded:
			labels = append(labels, "Metasploit module added")
		case ReopenNucleiAdded:
			labels = append(labels, "Nuclei template added")
		case ReopenExploitArtifactAdded:
			labels = append(labels, "new exploit artifact indexed")
		case ReopenEPSSThreshold:
			labels = append(labels, "EPSS crosses 0.90")
		default:
			labels = append(labels, string(t))
		}
	}
	return labels
}
