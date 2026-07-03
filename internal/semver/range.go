package semver

import (
	"strconv"
	"strings"
)

// Satisfies reports whether version satisfies an npm range spec.
//
// Supported grammar (the union of what appears in real package.json files and
// OSV ranges): "*"/""/"x"/"latest" (any), exact ("1.2.3"), caret ("^1.2.3"),
// tilde ("~1.2.3"), comparators (">=1.2.3 <2.0.0"), hyphen ranges
// ("1.2.3 - 2.3.4"), x-ranges ("1.2.x", "1.x"), and OR ("1.x || >=2.5.0").
//
// Prerelease versions only satisfy a comparator set when that set names a
// prerelease at the same [major,minor,patch], matching node-semver.
func Satisfies(version, spec string) bool {
	v, ok := Parse(version)
	if !ok {
		return false
	}
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" || spec == "x" || spec == "X" || spec == "latest" {
		return len(v.Prerelease) == 0
	}
	for _, or := range strings.Split(spec, "||") {
		comps, ok := parseComparatorSet(or)
		if !ok {
			continue
		}
		if comparatorsMatch(v, comps) {
			return true
		}
	}
	return false
}

type comparator struct {
	op string // one of < <= > >= =
	v  Version
}

func comparatorsMatch(v Version, comps []comparator) bool {
	if len(comps) == 0 {
		return false
	}
	// Prerelease gating: a prerelease version may only match if some comparator
	// references a prerelease at the same core tuple.
	if len(v.Prerelease) > 0 {
		allowed := false
		for _, c := range comps {
			if len(c.v.Prerelease) > 0 && sameCore(v, c.v) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	for _, c := range comps {
		if !c.matches(v) {
			return false
		}
	}
	return true
}

func sameCore(a, b Version) bool {
	return a.Major == b.Major && a.Minor == b.Minor && a.Patch == b.Patch
}

func (c comparator) matches(v Version) bool {
	cmp := Compare(v, c.v)
	switch c.op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	default: // "="
		return cmp == 0
	}
}

// parseComparatorSet turns one space-joined AND clause into comparators.
func parseComparatorSet(clause string) ([]comparator, bool) {
	clause = strings.TrimSpace(clause)
	if clause == "" || clause == "*" || clause == "x" || clause == "X" {
		return []comparator{{op: ">=", v: Version{}}}, true
	}

	// Hyphen range: "1.2.3 - 2.3.4"
	if strings.Contains(clause, " - ") {
		parts := strings.SplitN(clause, " - ", 2)
		lo, lok := hyphenLow(parts[0])
		hi, hok := hyphenHigh(parts[1])
		if !lok || !hok {
			return nil, false
		}
		return append(lo, hi...), true
	}

	var out []comparator
	for _, tok := range strings.Fields(clause) {
		cs, ok := parseComparator(tok)
		if !ok {
			return nil, false
		}
		out = append(out, cs...)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func parseComparator(tok string) ([]comparator, bool) {
	switch {
	case strings.HasPrefix(tok, "^"):
		return caretRange(tok[1:])
	case strings.HasPrefix(tok, "~"):
		return tildeRange(tok[1:])
	case strings.HasPrefix(tok, ">="):
		return single(">=", tok[2:])
	case strings.HasPrefix(tok, "<="):
		return single("<=", tok[2:])
	case strings.HasPrefix(tok, ">"):
		return single(">", tok[1:])
	case strings.HasPrefix(tok, "<"):
		return single("<", tok[1:])
	case strings.HasPrefix(tok, "="):
		return exactOrXRange(tok[1:])
	default:
		return exactOrXRange(tok)
	}
}

func single(op, raw string) ([]comparator, bool) {
	v, ok := Parse(raw)
	if !ok {
		return nil, false
	}
	return []comparator{{op: op, v: v}}, true
}

// exactOrXRange handles "1.2.3", "1.2.x", "1.x", "1".
func exactOrXRange(raw string) ([]comparator, bool) {
	lo, hi, exact, ok := xRangeBounds(raw)
	if !ok {
		return nil, false
	}
	if exact {
		return []comparator{{op: "=", v: lo}}, true
	}
	if isZeroCore(hi) { // bare "*"/"x" sentinel: match anything
		return []comparator{{op: ">=", v: Version{}}}, true
	}
	return []comparator{{op: ">=", v: lo}, {op: "<", v: hi}}, true
}

// xRangeBounds returns [lo, hi) bounds for an x-range, or an exact version.
func xRangeBounds(raw string) (lo Version, hi Version, exact bool, ok bool) {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	if raw == "" || raw == "*" || raw == "x" || raw == "X" {
		return Version{}, Version{}, false, true // any -> >=0.0.0 <∞; hi sentinel handled below
	}
	// Strip prerelease/build for x-range structural analysis but keep for exact.
	core := raw
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	isX := func(p string) bool { return p == "" || p == "x" || p == "X" || p == "*" }

	switch {
	case len(parts) >= 3 && !isX(parts[0]) && !isX(parts[1]) && !isX(parts[2]):
		v, pok := Parse(raw)
		if !pok {
			return Version{}, Version{}, false, false
		}
		return v, Version{}, true, true
	case len(parts) >= 2 && !isX(parts[0]) && !isX(parts[1]):
		// 1.2.x -> >=1.2.0 <1.3.0
		maj, mok := atoi(parts[0])
		min, nok := atoi(parts[1])
		if !mok || !nok {
			return Version{}, Version{}, false, false
		}
		return Version{Major: maj, Minor: min}, Version{Major: maj, Minor: min + 1}, false, true
	case len(parts) >= 1 && !isX(parts[0]):
		// 1.x -> >=1.0.0 <2.0.0
		maj, mok := atoi(parts[0])
		if !mok {
			return Version{}, Version{}, false, false
		}
		return Version{Major: maj}, Version{Major: maj + 1}, false, true
	default:
		return Version{}, Version{}, false, true
	}
}

func caretRange(raw string) ([]comparator, bool) {
	v, ok := Parse(raw)
	if !ok {
		return nil, false
	}
	lo := v
	var hi Version
	switch {
	case v.Major > 0:
		hi = Version{Major: v.Major + 1}
	case v.Minor > 0:
		hi = Version{Major: 0, Minor: v.Minor + 1}
	default:
		hi = Version{Major: 0, Minor: 0, Patch: v.Patch + 1}
	}
	return []comparator{{op: ">=", v: lo}, {op: "<", v: hi}}, true
}

func tildeRange(raw string) ([]comparator, bool) {
	v, ok := Parse(raw)
	if !ok {
		return nil, false
	}
	// ~1.2.3 -> >=1.2.3 <1.3.0 ; ~1.2 -> >=1.2.0 <1.3.0 ; ~1 -> >=1.0.0 <2.0.0
	hi := Version{Major: v.Major, Minor: v.Minor + 1}
	if rawHasOnlyMajor(raw) {
		hi = Version{Major: v.Major + 1}
	}
	return []comparator{{op: ">=", v: v}, {op: "<", v: hi}}, true
}

func rawHasOnlyMajor(raw string) bool {
	core := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	return !strings.Contains(core, ".")
}

func hyphenLow(raw string) ([]comparator, bool) {
	v, ok := Parse(raw)
	if !ok {
		return nil, false
	}
	return []comparator{{op: ">=", v: v}}, true
}

func hyphenHigh(raw string) ([]comparator, bool) {
	// Partial upper bound is inclusive of the whole range: "1.2" -> <1.3.0.
	core := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	parts := strings.Split(core, ".")
	switch len(parts) {
	case 1:
		maj, ok := atoi(parts[0])
		if !ok {
			return nil, false
		}
		return []comparator{{op: "<", v: Version{Major: maj + 1}}}, true
	case 2:
		maj, ok1 := atoi(parts[0])
		min, ok2 := atoi(parts[1])
		if !ok1 || !ok2 {
			return nil, false
		}
		return []comparator{{op: "<", v: Version{Major: maj, Minor: min + 1}}}, true
	default:
		v, ok := Parse(raw)
		if !ok {
			return nil, false
		}
		return []comparator{{op: "<=", v: v}}, true
	}
}

func isZeroCore(v Version) bool {
	return v.Major == 0 && v.Minor == 0 && v.Patch == 0 && len(v.Prerelease) == 0
}

func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
