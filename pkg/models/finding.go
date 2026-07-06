package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Priority is the exploitability classification (P0 = most severe).
type Priority int

const (
	PriorityP0 Priority = 0 // actively exploited in the wild (VulnCheck KEV)
	PriorityP1 Priority = 1 // weaponized — Nuclei/Metasploit/verified PoC
	PriorityP2 Priority = 2 // public proof-of-concept only
	PriorityP3 Priority = 3 // matched, no exploit signal indexed
	PriorityP4 Priority = 4 // no signal and low exploitation likelihood
)

func (p Priority) String() string {
	switch p {
	case PriorityP0:
		return "P0"
	case PriorityP1:
		return "P1"
	case PriorityP2:
		return "P2"
	case PriorityP3:
		return "P3"
	case PriorityP4:
		return "P4"
	default:
		return "P?"
	}
}

// Label returns a human-readable description of the priority level.
func (p Priority) Label() string {
	switch p {
	case PriorityP0:
		return "Actively Exploited"
	case PriorityP1:
		return "Weaponized"
	case PriorityP2:
		return "Exploit Available"
	case PriorityP3:
		return "Low Exploitability"
	case PriorityP4:
		return "Hygiene Fix"
	default:
		return "Unknown"
	}
}

// MarshalJSON encodes priority as P0–P4.
func (p Priority) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

// UnmarshalJSON accepts P0–P4 codes, legacy names, or numeric 0–4.
func (p *Priority) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*p = ParsePriority(s)
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*p = Priority(n)
		return nil
	}
	return fmt.Errorf("invalid priority JSON: %s", string(data))
}

// ParsePriority maps a priority code or legacy level name to Priority.
func ParsePriority(s string) Priority {
	switch strings.TrimSpace(s) {
	case "P0", "p0", "T0", "t0", "0",
		"Exploited", "exploited", "Actively Exploited", "actively exploited":
		return PriorityP0
	case "P1", "p1", "T1", "t1", "1",
		"Exploit-Ready", "exploit-ready", "Weaponized", "weaponized":
		return PriorityP1
	case "P2", "p2", "T2", "t2", "2",
		"PoC", "poc", "Exploit Available", "exploit available":
		return PriorityP2
	case "P3", "p3", "T3", "t3", "3",
		"Watch", "watch", "Low Exploitability", "low exploitability":
		return PriorityP3
	case "P4", "p4", "T4", "t4", "4",
		"Quiet", "quiet", "Hygiene Fix", "hygiene fix":
		return PriorityP4
	default:
		return PriorityP4
	}
}

// Verdict is the deterministic action a developer should take.
type Verdict string

const (
	VerdictFixNow  Verdict = "FIX NOW"
	VerdictFixSoon Verdict = "FIX SOON"
	VerdictOK      Verdict = "OK"

	// Advisory verdicts are used for scope-free lookups (`cve` command), where
	// no production/dev placement exists to ground a release-gate decision. They
	// describe patch urgency, not a release gate.
	VerdictPatchNow  Verdict = "PATCH NOW"
	VerdictPatchSoon Verdict = "PATCH SOON"
	VerdictWatch     Verdict = "WATCH"
)

// IsAction reports whether a verdict represents required action (used to group
// findings in reports and CI).
func (v Verdict) IsAction() bool {
	switch v {
	case VerdictFixNow, VerdictFixSoon, VerdictPatchNow, VerdictPatchSoon:
		return true
	default:
		return false
	}
}

// Citation backs a factual claim in a briefing.
type Citation struct {
	Claim  string `json:"claim"`
	Source Source `json:"source"`
	URL    string `json:"url,omitempty"`
	Title  string `json:"title,omitempty"`
}

// Classification is the exploit-risk assessment for a CVE.
type Classification struct {
	Priority   Priority       `json:"priority"`
	Confidence float64        `json:"confidence"`
	Band       ConfidenceBand `json:"confidenceBand"`
	Freshness  time.Time      `json:"freshness"`
	Evidence   []Citation     `json:"evidence"`
	Signals    Signals        `json:"signals"`
}

// ConfidenceBand is the human-readable bucket for a confidence score. It
// reflects how many sources corroborate the evidence and how authoritative
// they are — a single low-trust source lands in Low, three authoritative
// sources in High.
type ConfidenceBand string

const (
	ConfidenceHigh   ConfidenceBand = "High"
	ConfidenceMedium ConfidenceBand = "Medium"
	ConfidenceLow    ConfidenceBand = "Low"
)

// BandFor maps a confidence score to its band.
func BandFor(confidence float64) ConfidenceBand {
	switch {
	case confidence >= 0.85:
		return ConfidenceHigh
	case confidence >= 0.6:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// Signals summarizes raw intelligence inputs.
type Signals struct {
	KEV         bool    `json:"kev"`
	EPSS        float64 `json:"epss,omitempty"`
	Nuclei      bool    `json:"nuclei"`
	Metasploit  bool    `json:"metasploit"`
	ExploitDB   bool    `json:"exploitdb"`
	PoCVerified bool    `json:"pocVerified"`
	PoCPresent  bool    `json:"pocPresent"`
}

// Finding is a complete scan result row.
type Finding struct {
	Component         Component        `json:"component"`
	CveMatch          CveMatch         `json:"cve"`
	Classification    Classification   `json:"classification"`
	Remediation       *Remediation     `json:"remediation,omitempty"`
	Verdict           Verdict          `json:"verdict"`
	VerdictReason     string           `json:"verdictReason"`
	Receipts          []VerdictReceipt `json:"receipts,omitempty"`
	Briefing          string           `json:"briefing,omitempty"`
	ExposureNote      string           `json:"exposureNote,omitempty"`
	Suppressed        bool             `json:"suppressed,omitempty"`
	SuppressionReason string           `json:"suppressionReason,omitempty"`
	AcceptedRisk      bool             `json:"acceptedRisk,omitempty"`
	Reopened          bool             `json:"reopened,omitempty"`
	DecisionReason    string           `json:"decisionReason,omitempty"`
	ReopenSummary     string           `json:"reopenSummary,omitempty"`
	PackageContext    *PackageContext  `json:"packageContext,omitempty"`
}

// ScanMeta holds scan metadata.
type ScanMeta struct {
	Timestamp       time.Time           `json:"timestamp"`
	SnapshotVersion string              `json:"snapshotVersion,omitempty"`
	SnapshotHash    string              `json:"snapshotHash,omitempty"`
	InputPath       string              `json:"inputPath,omitempty"`
	InputHash       string              `json:"inputHash,omitempty"`
	DurationMS      int64               `json:"durationMs"`
	ComponentCount  int                 `json:"componentCount"`
	FindingCount    int                 `json:"findingCount"`
	OSVCacheHits    int                 `json:"osvCacheHits,omitempty"`
	OSVQueries      int                 `json:"osvQueries,omitempty"`
	OSVChunks       int                 `json:"osvChunks,omitempty"`
	SuppressedCount int                 `json:"suppressedCount,omitempty"`
	AcceptedCount   int                 `json:"acceptedCount,omitempty"`
	ReopenedCount   int                 `json:"reopenedCount,omitempty"`
	ResolvedPackage string              `json:"resolvedPackage,omitempty"`
	PackageNote     string              `json:"packageNote,omitempty"`
	PackageContext  *PackageContext     `json:"packageContext,omitempty"`
	DependencyTree  *DependencyTreeMeta `json:"dependencyTree,omitempty"`
	Coverage        *ScanCoverageMeta   `json:"coverage,omitempty"`
	InputMode       InputMode           `json:"inputMode,omitempty"`
}

// ScanCoverageMeta describes lockfile and transitive resolution completeness.
type ScanCoverageMeta struct {
	Status              string `json:"status"`
	HasLockfile         bool   `json:"hasLockfile"`
	ManifestOnly        bool   `json:"manifestOnly,omitempty"`
	UnresolvedCount     int    `json:"unresolvedCount,omitempty"`
	DirectCount         int    `json:"directCount,omitempty"`
	TransitiveCount     int    `json:"transitiveCount,omitempty"`
	TotalCount          int    `json:"totalCount,omitempty"`
	PeerDependencyCount int    `json:"peerDependencyCount,omitempty"`
	// SnapshotMode is "online" (live OSV API), "full-offline-db" (a complete
	// `depfuse collect` database used offline), or "embedded-snapshot" (the
	// weaponized-only index bundled with the binary — quiet/non-tiering
	// advisories are not indexed until `depfuse collect` runs).
	SnapshotMode string `json:"snapshotMode,omitempty"`
	Message      string `json:"message"`
}

func (c *ScanCoverageMeta) IsIncomplete() bool {
	return c != nil && c.Status == "incomplete"
}

// DependencyTreeMeta summarizes registry-resolved transitive dependencies.
type DependencyTreeMeta struct {
	Total      int    `json:"total"`
	Direct     int    `json:"direct"`
	Transitive int    `json:"transitive"`
	Root       string `json:"root,omitempty"`
}

// InputMode identifies how the scan was invoked.
type InputMode string

const (
	InputModeCVE InputMode = "cve"
)

// ScanSummary aggregates per-priority and per-action counts.
type ScanSummary struct {
	Total int `json:"total"`
	P0    int `json:"p0"`
	P1    int `json:"p1"`
	P2    int `json:"p2"`
	P3    int `json:"p3"`
	P4    int `json:"p4"`
	// Per action.
	FixNow  int `json:"fixNow"`
	FixSoon int `json:"fixSoon"`
	OK      int `json:"ok"`
}

// WeaponizedExposure counts P0 + P1 — dependencies with public exploit
// evidence (KEV, weaponized tooling, or a verified PoC), the buckets that
// drive FIX NOW. This is not a claim of app-level reachability.
func (s ScanSummary) WeaponizedExposure() int { return s.P0 + s.P1 }

// Backlog counts P3 + P4 — no actionable exploit signal.
func (s ScanSummary) Backlog() int { return s.P3 + s.P4 }

// CurrentSchemaVersion is the ScanResult JSON contract version. Bump it (and
// schemas/scan-result.schema.json) only on a breaking change to top-level
// field names or types — additive fields don't require a bump.
const CurrentSchemaVersion = "1.0"

// ScanResult is the full scan output.
type ScanResult struct {
	SchemaVersion string       `json:"schemaVersion"`
	Meta          ScanMeta     `json:"meta"`
	Summary       ScanSummary  `json:"summary"`
	Findings      []Finding    `json:"findings"`
	Suppressed    []Finding    `json:"suppressed,omitempty"`
	Accepted      []Finding    `json:"accepted,omitempty"`
	Watch         *WatchResult `json:"watch,omitempty"`
	Delta         *ScanDelta   `json:"delta,omitempty"`
	// Unresolved lists lockfile-pinned components that could not be resolved to
	// a concrete version and were therefore excluded from OSV matching — never
	// silently dropped. See Component.UnresolvedReason for why.
	Unresolved  []Component               `json:"unresolved,omitempty"`
	ShowIgnored bool                      `json:"-"`
	Verbose     bool                      `json:"-"`
	ShowTree    bool                      `json:"-"` // expand full shadow dep tree in CLI output
	Packages    map[string]PackageContext `json:"packages,omitempty"`
	// Components holds the full flat package list for shadow-dep rendering.
	// Excluded from JSON to keep scan output compact; use --format json --tree
	// to get full tree data via the shadowDependencies field.
	Components []Component `json:"-"`
}
