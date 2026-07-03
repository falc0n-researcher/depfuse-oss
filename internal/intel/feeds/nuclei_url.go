package feeds

import (
	"path/filepath"
	"strings"
)

const nucleiRepoBlobBase = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"

// NucleiBlobURL returns a GitHub blob URL for a template path relative to repo root.
func NucleiBlobURL(relPath string) string {
	relPath = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(relPath)), "/")
	if relPath == "" {
		return "https://github.com/projectdiscovery/nuclei-templates"
	}
	return nucleiRepoBlobBase + relPath
}

// IsGenericNucleiRepoURL reports URLs that point at the repo root, not a template file.
func IsGenericNucleiRepoURL(u string) bool {
	u = strings.TrimSuffix(strings.TrimSpace(u), "/")
	u = strings.TrimSuffix(u, ".git")
	return u == "https://github.com/projectdiscovery/nuclei-templates"
}

// InferNucleiTemplatePath guesses the standard http/cves/{year}/{CVE}.yaml layout.
func InferNucleiTemplatePath(cveID string) string {
	if !strings.HasPrefix(cveID, "CVE-") {
		return ""
	}
	parts := strings.Split(cveID, "-")
	if len(parts) < 2 || len(parts[1]) != 4 {
		return ""
	}
	return filepath.ToSlash(filepath.Join("http", "cves", parts[1], cveID+".yaml"))
}
