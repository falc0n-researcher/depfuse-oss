package lockfile

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/purl"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

type bunLock struct {
	Packages map[string]json.RawMessage `json:"packages"`
}

type bunPackageMeta struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParseBun parses bun.lock (text JSON lockfile).
func ParseBun(manifestPath string, deps ManifestDeps, lockPath string) ([]models.Component, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	data = stripBunComments(data)

	var lock bunLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	versions := map[string]string{}
	for key, raw := range lock.Packages {
		if name, ver := parseBunPackageKey(key); name != "" && ver != "" {
			versions[name] = ver
			continue
		}
		var meta bunPackageMeta
		if err := json.Unmarshal(raw, &meta); err == nil && meta.Version != "" {
			name := meta.Name
			if name == "" {
				name = key
			}
			versions[name] = meta.Version
		}
	}

	var out []models.Component
	for name, version := range versions {
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

func stripBunComments(data []byte) []byte {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		lines = append(lines, line)
	}
	return []byte(strings.Join(lines, "\n"))
}

func parseBunPackageKey(key string) (name, version string) {
	if strings.HasPrefix(key, "@") {
		rest := key[1:]
		slash := strings.Index(rest, "/")
		if slash < 0 {
			return "", ""
		}
		scope := rest[:slash]
		rest = rest[slash+1:]
		at := strings.LastIndex(rest, "@")
		if at <= 0 {
			return "", ""
		}
		return "@" + scope + "/" + rest[:at], rest[at+1:]
	}
	at := strings.LastIndex(key, "@")
	if at <= 0 {
		return "", ""
	}
	return key[:at], key[at+1:]
}
