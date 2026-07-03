package resolve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// NormalizeScanRoot accepts a project directory or a package.json file path.
func NormalizeScanRoot(path string) (string, error) {
	if path == "" {
		return ".", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return path, nil
	}
	if strings.EqualFold(filepath.Base(path), "package.json") {
		return filepath.Dir(path), nil
	}
	return "", fmt.Errorf("scan path must be a directory or package.json file, got %q", path)
}

// UsesManifestOnlyResolution reports true when any component came from a
// manifest without a lockfile (it carries a range Spec).
func UsesManifestOnlyResolution(components []models.Component) bool {
	for _, c := range components {
		if c.Spec != "" || c.Version == "*" {
			return true
		}
	}
	return false
}

// UnresolvedComponents returns components that could not be pinned to a
// concrete version (and are therefore excluded from matching).
func UnresolvedComponents(components []models.Component) []models.Component {
	var out []models.Component
	for _, c := range components {
		if c.Unresolved {
			out = append(out, c)
		}
	}
	return out
}
