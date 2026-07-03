package verdict

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// Compute returns the deterministic action for a finding. The confidence band
// does not change the action (the gate stays deterministic on level + scope) —
// it appends a caveat when an actionable verdict rests on thin evidence, so a
// developer trusts the gate instead of muting the tool.
func Compute(comp models.Component, priority models.Priority, band models.ConfidenceBand) (models.Verdict, string) {
	var v models.Verdict
	var reason string
	switch {
	case priority == models.PriorityP0 && comp.Scope == models.ScopeProd:
		v, reason = models.VerdictFixNow, fmt.Sprintf("P0 actively exploited — fix production dependency %s@%s before release", comp.Name, comp.Version)
	case priority == models.PriorityP1 && comp.Scope == models.ScopeProd:
		v, reason = models.VerdictFixNow, fmt.Sprintf("P1 weaponized — fix production dependency %s@%s before release", comp.Name, comp.Version)
	case priority == models.PriorityP1 && comp.Scope == models.ScopeDev:
		v, reason = models.VerdictFixSoon, fmt.Sprintf("P1 weaponized in dev/build tooling %s@%s — fix soon, not release-blocking", comp.Name, comp.Version)
	case priority == models.PriorityP2:
		v, reason = models.VerdictFixSoon, fmt.Sprintf("P2 exploit available for %s@%s — fix soon", comp.Name, comp.Version)
	default:
		return models.VerdictOK, fmt.Sprintf("No known exploit for %s@%s — OK to ship; monitor for changes", comp.Name, comp.Version)
	}
	return v, withConfidenceCaveat(reason, band)
}

// ComputeAdvisory returns a scope-free action for advisory-only lookups (the
// `cve` command), where there is no prod/dev placement to ground a release-gate
// decision. The action reflects patch urgency derived from the priority alone.
func ComputeAdvisory(priority models.Priority, band models.ConfidenceBand) (models.Verdict, string) {
	switch priority {
	case models.PriorityP0:
		return models.VerdictPatchNow, withConfidenceCaveat("P0 actively exploited (VulnCheck KEV) — patch now wherever this package is used", band)
	case models.PriorityP1:
		return models.VerdictPatchNow, withConfidenceCaveat("P1 weaponized — patch now wherever this package is used", band)
	case models.PriorityP2:
		return models.VerdictPatchSoon, withConfidenceCaveat("P2 exploit available — patch soon when this package is in your dependency tree", band)
	default:
		return models.VerdictWatch, "No known exploit — monitor; reassess if a lockfile match appears"
	}
}

// withConfidenceCaveat appends a verification note when an actionable verdict
// rests on a single low-trust source.
func withConfidenceCaveat(reason string, band models.ConfidenceBand) string {
	if band == models.ConfidenceLow {
		return reason + " (low confidence — single unverified source, confirm before acting)"
	}
	return reason
}

// ShouldFailCI returns true if the finding should fail CI given fail tiers.
func ShouldFailCI(comp models.Component, priority models.Priority, failTiers map[models.Priority]bool) bool {
	if comp.Scope != models.ScopeProd {
		return false
	}
	return failTiers[priority]
}

// ParseFailTiers parses comma-separated priority codes (P0–P2 default).
// Legacy aliases (exploited, t0, exploit-ready, poc, etc.) are accepted.
func ParseFailTiers(s string) map[models.Priority]bool {
	out := map[models.Priority]bool{}
	if s == "" {
		out[models.PriorityP0] = true
		out[models.PriorityP1] = true
		return out
	}
	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(strings.ToLower(part)) {
		case "p0", "t0", "exploited":
			out[models.PriorityP0] = true
		case "p1", "t1", "exploit-ready", "exploitready", "weaponized":
			out[models.PriorityP1] = true
		case "p2", "t2", "poc":
			out[models.PriorityP2] = true
		}
	}
	return out
}
