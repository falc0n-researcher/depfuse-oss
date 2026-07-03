package rollup

import (
	"sort"

	"github.com/falc0n-researcher/depfuse-oss/internal/semver"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// UpgradeRollup groups findings under a declared dependency for remediation planning.
type UpgradeRollup struct {
	RootName     string
	RootVersion  string
	FindingCount int
	PackageCount int
	Worst        models.Priority
	FixVersion   string
	Packages     []string
}

// BuildUpgradeRollup suggests direct-dependency upgrades that clear the most findings.
func BuildUpgradeRollup(components []models.Component, findings []models.Finding) []UpgradeRollup {
	directVer := map[string]string{}
	for _, c := range components {
		if c.Direct {
			directVer[c.Name] = c.Version
		}
	}

	type bucket struct {
		root     string
		findings []models.Finding
		pkgs     map[string]bool
		worst    models.Priority
		fix      string
	}
	groups := map[string]*bucket{}

	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		root := f.Component.Name
		if len(f.Component.Path) > 0 {
			root = f.Component.Path[0]
		} else if !f.Component.Direct {
			continue
		}
		b := groups[root]
		if b == nil {
			b = &bucket{root: root, pkgs: map[string]bool{}, worst: models.PriorityP4}
			groups[root] = b
		}
		b.findings = append(b.findings, f)
		b.pkgs[f.Component.Name] = true
		if f.Classification.Priority < b.worst {
			b.worst = f.Classification.Priority
		}
		if fix := bestFixVersion(f); fix != "" {
			b.fix = maxFixVersion(b.fix, fix)
		}
	}

	out := make([]UpgradeRollup, 0, len(groups))
	for _, b := range groups {
		if len(b.findings) == 0 {
			continue
		}
		pkgs := make([]string, 0, len(b.pkgs))
		for name := range b.pkgs {
			pkgs = append(pkgs, name)
		}
		sort.Strings(pkgs)
		out = append(out, UpgradeRollup{
			RootName:     b.root,
			RootVersion:  directVer[b.root],
			FindingCount: len(b.findings),
			PackageCount: len(b.pkgs),
			Worst:        b.worst,
			FixVersion:   b.fix,
			Packages:     pkgs,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Worst != out[j].Worst {
			return out[i].Worst < out[j].Worst
		}
		if out[i].FindingCount != out[j].FindingCount {
			return out[i].FindingCount > out[j].FindingCount
		}
		return out[i].RootName < out[j].RootName
	})
	return out
}

func bestFixVersion(f models.Finding) string {
	if f.Remediation != nil && f.Remediation.FixAvailable && f.Remediation.FixVersion != "" {
		return f.Remediation.FixVersion
	}
	if len(f.CveMatch.FixedVersions) > 0 {
		return f.CveMatch.FixedVersions[0]
	}
	return ""
}

func maxFixVersion(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if semver.CompareStr(b, a) > 0 {
		return b
	}
	return a
}
