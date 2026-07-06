package lockfile

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/purl"
	"github.com/falc0n-researcher/depfuse-oss/internal/semver"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// ManifestDeps holds direct dependency names and version specs from package.json.
type ManifestDeps struct {
	Prod  map[string]bool
	Dev   map[string]bool
	Specs map[string]string // name -> raw version spec (range or exact)
}

// PathConfidence values for models.Component.PathConfidence.
const (
	// PathConfidenceExact means Path reflects the true dependency chain,
	// reconstructed from a lockfile format with recorded parent/child edges
	// (npm package-lock v1/v2/v3).
	PathConfidenceExact = "exact"
	// PathConfidenceLow means the lockfile format only yields a flat,
	// unranked package list (yarn, pnpm, bun) — Path is just [Name], not a
	// verified dependency chain.
	PathConfidenceLow = "low"
)

// LoadManifestDeps reads package.json dependency sections.
func LoadManifestDeps(manifestPath string) (ManifestDeps, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return ManifestDeps{}, err
	}
	var raw struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return ManifestDeps{}, err
	}
	specs := make(map[string]string, len(raw.Dependencies)+len(raw.DevDependencies))
	for k, v := range raw.Dependencies {
		specs[k] = v
	}
	for k, v := range raw.DevDependencies {
		if _, ok := specs[k]; !ok {
			specs[k] = v
		}
	}
	return ManifestDeps{
		Prod:  keys(raw.Dependencies),
		Dev:   keys(raw.DevDependencies),
		Specs: specs,
	}, nil
}

// ParseManifestOnly returns direct dependencies when no lockfile exists.
//
// Exact specs (e.g. "4.17.20") are pinned immediately. Range specs are left
// Unresolved with the raw Spec preserved so the caller can resolve them against
// the npm registry (online) before matching — never silently treated as "*".
func ParseManifestOnly(manifestPath string, deps ManifestDeps) ([]models.Component, error) {
	build := func(name string, scope models.Scope) models.Component {
		spec := deps.Specs[name]
		c := models.Component{
			Name:     name,
			Scope:    scope,
			Direct:   true,
			Path:     []string{name},
			Manifest: manifestPath,
			Spec:     spec,
		}
		if ver, ok := exactSpecVersion(spec); ok {
			c.Version = ver
			c.PURL = purl.NPM(name, ver)
		} else {
			c.Unresolved = true
			c.PURL = purl.NPM(name, "*")
		}
		return c
	}
	var out []models.Component
	for name := range deps.Prod {
		out = append(out, build(name, models.ScopeProd))
	}
	for name := range deps.Dev {
		out = append(out, build(name, models.ScopeDev))
	}
	return out, nil
}

// exactSpecVersion returns the concrete version when spec names a single version.
func exactSpecVersion(spec string) (string, bool) {
	s := strings.TrimSpace(spec)
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v"))
	if !semver.IsExact(s) {
		return "", false
	}
	return s, true
}

type npmLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
	Dependencies    map[string]npmLockDep     `json:"dependencies"`
}

type npmLockPackage struct {
	Version      string            `json:"version"`
	Dev          bool              `json:"dev"`
	Dependencies map[string]string `json:"dependencies"`
}

type npmLockDep struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

// ParseNPM parses package-lock.json v2/v3.
func ParseNPM(manifestPath string, deps ManifestDeps, lockPath string) ([]models.Component, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	if lock.LockfileVersion >= 2 && len(lock.Packages) > 0 {
		return parseNPMPackages(manifestPath, lock.Packages, deps)
	}
	return parseNPMLegacy(manifestPath, lock.Dependencies, deps)
}

func parseNPMPackages(manifestPath string, packages map[string]npmLockPackage, deps ManifestDeps) ([]models.Component, error) {
	paths := npmDependencyPaths(packages, deps)
	var out []models.Component
	for pkgPath, pkg := range packages {
		if pkgPath == "" {
			continue
		}
		name := npmPackageName(pkgPath)
		if name == "" || pkg.Version == "" {
			continue
		}
		scope := models.ScopeProd
		if pkg.Dev || deps.Dev[name] {
			scope = models.ScopeDev
		}
		direct := deps.Prod[name] || deps.Dev[name]
		chain := paths[name]
		if len(chain) == 0 {
			chain = []string{name}
		}
		out = append(out, models.Component{
			Name:           name,
			Version:        pkg.Version,
			PURL:           purl.NPM(name, pkg.Version),
			Scope:          scope,
			Direct:         direct,
			Path:           chain,
			Manifest:       manifestPath,
			PathConfidence: PathConfidenceExact,
		})
	}
	return out, nil
}

func npmDependencyPaths(packages map[string]npmLockPackage, deps ManifestDeps) map[string][]string {
	children := map[string][]string{}
	for pkgPath, pkg := range packages {
		if pkgPath == "" || pkg.Version == "" {
			continue
		}
		parent := npmPackageName(pkgPath)
		for child := range pkg.Dependencies {
			children[parent] = appendUnique(children[parent], child)
		}
	}

	direct := map[string]bool{}
	for k := range deps.Prod {
		direct[k] = true
	}
	for k := range deps.Dev {
		direct[k] = true
	}

	paths := map[string][]string{}
	var walk func(node string, chain []string, seen map[string]bool)
	walk = func(node string, chain []string, seen map[string]bool) {
		if seen[node] {
			return
		}
		seen[node] = true
		chain = append(chain, node)
		if prev, ok := paths[node]; !ok || len(chain) < len(prev) {
			paths[node] = append([]string(nil), chain...)
		}
		for _, child := range children[node] {
			childSeen := map[string]bool{}
			for k, v := range seen {
				childSeen[k] = v
			}
			walk(child, chain, childSeen)
		}
	}
	for name := range direct {
		walk(name, nil, map[string]bool{})
	}
	return paths
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func parseNPMLegacy(manifestPath string, rootDeps map[string]npmLockDep, deps ManifestDeps) ([]models.Component, error) {
	var out []models.Component
	var walk func(name string, dep npmLockDep, inheritedDev bool, chain []string)
	walk = func(name string, dep npmLockDep, inheritedDev bool, chain []string) {
		if dep.Version == "" {
			return
		}
		scope := models.ScopeProd
		if dep.Dev || inheritedDev || deps.Dev[name] {
			scope = models.ScopeDev
		}
		direct := deps.Prod[name] || deps.Dev[name]
		path := append(append([]string(nil), chain...), name)
		out = append(out, models.Component{
			Name:           name,
			Version:        dep.Version,
			PURL:           purl.NPM(name, dep.Version),
			Scope:          scope,
			Direct:         direct,
			Path:           path,
			Manifest:       manifestPath,
			PathConfidence: PathConfidenceExact,
		})
		for childName, childDep := range dep.Dependencies {
			walk(childName, childDep, scope == models.ScopeDev, path)
		}
	}
	for name, dep := range rootDeps {
		walk(name, dep, false, nil)
	}
	return out, nil
}

func npmPackageName(pkgPath string) string {
	pkgPath = strings.TrimPrefix(pkgPath, "node_modules/")
	if strings.Contains(pkgPath, "node_modules/") {
		idx := strings.LastIndex(pkgPath, "node_modules/")
		pkgPath = pkgPath[idx+len("node_modules/"):]
	}
	if strings.HasPrefix(pkgPath, "@") {
		parts := strings.SplitN(pkgPath, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}
	parts := strings.SplitN(pkgPath, "/", 2)
	return parts[0]
}

func keys(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// ParseYarn parses yarn.lock v1 or Yarn Berry (v2+) format.
func ParseYarn(manifestPath string, deps ManifestDeps, lockPath string) ([]models.Component, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	content := string(data)
	var entries map[string]string
	if isYarnBerryLock(content) {
		entries = parseYarnBerryLock(content)
	} else {
		entries = parseYarnLock(content)
	}
	var out []models.Component
	for name, version := range entries {
		scope := models.ScopeProd
		if deps.Dev[name] {
			scope = models.ScopeDev
		}
		direct := deps.Prod[name] || deps.Dev[name]
		out = append(out, models.Component{
			Name:           name,
			Version:        version,
			PURL:           purl.NPM(name, version),
			Scope:          scope,
			Direct:         direct,
			Path:           []string{name},
			Manifest:       manifestPath,
			PathConfidence: PathConfidenceLow,
		})
	}
	return out, nil
}

func parseYarnLock(content string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(content, "\n")
	var currentKey string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "# yarn lockfile v1" {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			currentKey = strings.TrimSuffix(line, ":")
			continue
		}
		if strings.HasPrefix(line, "version ") && currentKey != "" {
			ver := strings.Trim(strings.TrimPrefix(line, "version "), "\"")
			name := yarnPackageName(currentKey)
			if name != "" {
				out[name] = ver
			}
		}
	}
	return out
}

func yarnPackageName(key string) string {
	at := strings.LastIndex(key, "@")
	if at <= 0 {
		return key
	}
	return key[:at]
}

// ParsePNPM parses pnpm-lock.yaml package entries.
func ParsePNPM(manifestPath string, deps ManifestDeps, lockPath string) ([]models.Component, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	packages := parsePNPMPackages(string(data))
	var out []models.Component
	for name, version := range packages {
		scope := models.ScopeProd
		if deps.Dev[name] {
			scope = models.ScopeDev
		}
		direct := deps.Prod[name] || deps.Dev[name]
		out = append(out, models.Component{
			Name:           name,
			Version:        version,
			PURL:           purl.NPM(name, version),
			Scope:          scope,
			Direct:         direct,
			Path:           []string{name},
			Manifest:       manifestPath,
			PathConfidence: PathConfidenceLow,
		})
	}
	return out, nil
}

func parsePNPMPackages(content string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(content, "\n")
	inPackages := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "packages:" {
			inPackages = true
			continue
		}
		if inPackages && !strings.HasPrefix(line, "  ") && strings.HasSuffix(trimmed, ":") {
			if trimmed != "packages:" {
				break
			}
		}
		if inPackages && isPNPMPackageKeyLine(line, trimmed) {
			entry := strings.TrimSuffix(trimmed, ":")
			entry = strings.TrimPrefix(entry, "/")
			at := strings.LastIndex(entry, "@")
			if at <= 0 {
				continue
			}
			name := entry[:at]
			version := entry[at+1:]
			if paren := strings.Index(version, "("); paren > 0 {
				version = version[:paren]
			}
			out[name] = version
		}
	}
	return out
}

// isPNPMPackageKeyLine reports whether line is a top-level entry under
// packages: (exactly 2-space indent — nested metadata like "resolution:" or
// "engines:" is indented 4+). lockfileVersion 6 prefixes keys with "/" (e.g.
// "  /lodash@4.17.21:"); lockfileVersion 9 dropped the leading slash (e.g.
// "  lodash@4.17.21:"), so both are accepted here.
func isPNPMPackageKeyLine(line, trimmed string) bool {
	if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
		return false
	}
	if !strings.HasSuffix(trimmed, ":") {
		return false
	}
	key := strings.TrimPrefix(trimmed, "/")
	return strings.Contains(key, "@")
}
