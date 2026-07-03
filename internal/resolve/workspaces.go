package resolve

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DiscoverWorkspaces reads workspace globs from a package.json (npm/yarn/pnpm).
func DiscoverWorkspaces(manifestPath string) ([]string, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if len(raw.Workspaces) == 0 {
		return nil, nil
	}

	var patterns []string
	if err := json.Unmarshal(raw.Workspaces, &patterns); err == nil && len(patterns) > 0 {
		return patterns, nil
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(raw.Workspaces, &obj); err == nil && len(obj.Packages) > 0 {
		return obj.Packages, nil
	}
	return nil, nil
}

// ExpandWorkspaceGlobs resolves workspace patterns to package.json paths under root.
func ExpandWorkspaceGlobs(root string, patterns []string) ([]string, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	var manifests []string

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		// npm allows "packages/*"; normalize for filepath.Glob.
		globPath := filepath.Join(root, filepath.FromSlash(pattern), "package.json")
		matches, err := filepath.Glob(globPath)
		if err != nil {
			return nil, fmt.Errorf("workspace glob %q: %w", pattern, err)
		}
		for _, m := range matches {
			if seen[m] {
				continue
			}
			if skipWorkspaceManifest(m) {
				continue
			}
			seen[m] = true
			manifests = append(manifests, m)
		}
	}
	return manifests, nil
}

func skipWorkspaceManifest(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, p := range parts {
		if p == "node_modules" {
			return true
		}
	}
	return false
}
