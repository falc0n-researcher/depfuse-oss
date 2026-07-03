// Package remediation turns a matched advisory's fixed-version list into an
// actionable, blast-radius-aware upgrade recommendation. It answers the
// developer's real next question after "this is risky": can I fix it, what is
// the minimal safe version, and will the upgrade break me?
package remediation

import (
	"github.com/falc0n-researcher/depfuse-oss/internal/semver"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// Assess computes the remediation for a component at `installed`, given the
// advisory's published fixed versions. The recommended fix is the smallest
// published version strictly newer than the installed one (the cheapest upgrade
// that clears the vulnerability); the jump classifies its semver blast radius.
func Assess(installed string, fixedVersions []string) models.Remediation {
	r := models.Remediation{Installed: installed}

	iv, instOK := semver.Parse(installed)

	var (
		best     semver.Version
		bestStr  string
		haveBest bool
		anyFixed bool
	)
	for _, raw := range fixedVersions {
		fv, ok := semver.Parse(raw)
		if !ok {
			continue
		}
		anyFixed = true
		// Only forward fixes are usable; a fix at or below the installed version
		// belongs to a different (older) affected branch.
		if instOK && semver.Compare(fv, iv) <= 0 {
			continue
		}
		if !haveBest || semver.Compare(fv, best) < 0 {
			best, bestStr, haveBest = fv, raw, true
		}
	}

	if !haveBest {
		// Either nothing is published, or fixes exist only on a branch at/below
		// the installed version (ambiguous — defer to the advisory).
		if anyFixed {
			r.Jump = models.JumpUnknown
		}
		return r
	}

	r.FixAvailable = true
	r.FixVersion = bestStr
	if !instOK {
		r.Jump = models.JumpUnknown
		return r
	}

	switch {
	case best.Major > iv.Major:
		r.Jump = models.JumpMajor
		r.Breaking = true
	case best.Minor > iv.Minor:
		r.Jump = models.JumpMinor
	default:
		r.Jump = models.JumpPatch
	}
	return r
}
