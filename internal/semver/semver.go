// Package semver implements the subset of npm semantic-versioning needed by
// Depfuse: version comparison (for evaluating OSV affected ranges) and range
// satisfaction (for resolving package.json specs without a lockfile).
//
// It is intentionally focused. It handles the version and range grammar that
// appears in real npm manifests and OSV "ECOSYSTEM" ranges; it is not a
// complete reimplementation of node-semver.
package semver

import (
	"strconv"
	"strings"
)

// Version is a parsed semantic version. Build metadata is ignored for ordering.
type Version struct {
	Major, Minor, Patch int
	Prerelease          []string // dot-separated identifiers, empty for release versions
	raw                 string
}

// Parse parses an npm/semver version string. Leading "v"/"=" and surrounding
// whitespace are tolerated. It returns false when the core (major.minor.patch)
// cannot be read.
func Parse(s string) (Version, bool) {
	raw := s
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, false
	}

	// Split off build metadata (ignored) then prerelease.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre []string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		preStr := s[i+1:]
		s = s[:i]
		if preStr != "" {
			pre = strings.Split(preStr, ".")
		}
	}

	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return Version{}, false
	}
	nums := []int{0, 0, 0}
	for i := range parts {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return Version{}, false
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Prerelease: pre, raw: raw}, true
}

// Compare returns -1, 0, or 1 comparing a to b by semver precedence.
func Compare(a, b Version) int {
	if c := cmpInt(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpInt(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpInt(a.Patch, b.Patch); c != 0 {
		return c
	}
	return comparePrerelease(a.Prerelease, b.Prerelease)
}

// CompareStr compares two version strings. Unparseable versions sort last but
// deterministically (by raw string) so callers never panic on bad data.
func CompareStr(a, b string) int {
	va, oka := Parse(a)
	vb, okb := Parse(b)
	switch {
	case oka && okb:
		return Compare(va, vb)
	case oka:
		return -1
	case okb:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func comparePrerelease(a, b []string) int {
	// A version without prerelease ranks higher than one with.
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := comparePreIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func comparePreIdent(a, b string) int {
	an, aerr := strconv.Atoi(a)
	bn, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		return cmpInt(an, bn)
	case aerr == nil: // numeric identifiers have lower precedence than alphanumeric
		return -1
	case berr == nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// IsExact reports whether a spec names a single concrete version (e.g. "1.2.3",
// "=1.2.3", "v1.2.3") with no range operators.
func IsExact(spec string) bool {
	s := strings.TrimSpace(spec)
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, " ^~><|*xX") {
		return false
	}
	if strings.Contains(s, " - ") {
		return false
	}
	_, ok := Parse(s)
	return ok
}

// MaxSatisfying returns the highest version in versions that satisfies spec, or
// "" if none do. Prerelease versions are only returned when the spec itself
// references a prerelease, matching npm behaviour closely enough for triage.
func MaxSatisfying(versions []string, spec string) string {
	best := ""
	var bestV Version
	for _, v := range versions {
		pv, ok := Parse(v)
		if !ok {
			continue
		}
		if !Satisfies(v, spec) {
			continue
		}
		if best == "" || Compare(pv, bestV) > 0 {
			best, bestV = v, pv
		}
	}
	return best
}
