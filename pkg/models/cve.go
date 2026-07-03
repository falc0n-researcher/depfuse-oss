package models

import (
	"sort"
	"time"
)

// AffectedPackage is one package entry from an OSV advisory affected list.
type AffectedPackage struct {
	Name         string `json:"name"`
	Ecosystem    string `json:"ecosystem,omitempty"`
	FixedVersion string `json:"fixedVersion,omitempty"`
}

// CveMatch is a CVE matched to a component via OSV.
type CveMatch struct {
	CVEID            string            `json:"cveId"`
	OSVID            string            `json:"osvId,omitempty"`
	GHSAID           string            `json:"ghsaId,omitempty"`
	Aliases          []string          `json:"aliases,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Details          string            `json:"details,omitempty"`
	Severity         string            `json:"severity,omitempty"`
	Published        time.Time         `json:"published,omitempty"`
	FixedVersions    []string          `json:"fixedVersions,omitempty"`
	AffectedPackages []AffectedPackage `json:"affectedPackages,omitempty"`
	References       []string          `json:"references,omitempty"`
}

// NPMAffectedPackages returns deduplicated npm entries from the advisory affected list.
func (c CveMatch) NPMAffectedPackages() []AffectedPackage {
	seen := map[string]bool{}
	var out []AffectedPackage
	for _, p := range c.AffectedPackages {
		if p.Name == "" || (p.Ecosystem != "" && p.Ecosystem != "npm") {
			continue
		}
		if seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// AdvisoryID returns the best identifier for a matched advisory (CVE, GHSA, or OSV id).
func (c CveMatch) AdvisoryID() string {
	if c.CVEID != "" {
		return c.CVEID
	}
	if c.GHSAID != "" {
		return c.GHSAID
	}
	if c.OSVID != "" {
		return c.OSVID
	}
	for _, a := range c.Aliases {
		if a != "" {
			return a
		}
	}
	return ""
}
