package report

import (
	"os"
	"path/filepath"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// OutputPaths names report artifacts for a scan mode.
type OutputPaths struct {
	Dir      string
	HTMLName string
	MDName   string
}

// OutputPathsFor returns disk report paths for project, package, and CVE scans.
func OutputPathsFor(outDir string, result models.ScanResult, packageLookup string) OutputPaths {
	dir := outDir
	if dir == "" {
		dir = intel.HomeDir()
	}
	if packageLookup != "" {
		return OutputPaths{Dir: dir, HTMLName: "report-package.html", MDName: "report-package.md"}
	}
	if result.Meta.InputMode == models.InputModeCVE {
		return OutputPaths{Dir: dir, HTMLName: "report-cve.html", MDName: "report-cve.md"}
	}
	return OutputPaths{Dir: dir, HTMLName: "report.html", MDName: "report.md"}
}

// WriteOutputsAt writes report.md/html using mode-specific filenames.
func WriteOutputsAt(paths OutputPaths, formats []string, result models.ScanResult) error {
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		return err
	}
	for _, f := range formats {
		switch f {
		case "md", "markdown":
			if err := RenderMarkdown(filepath.Join(paths.Dir, paths.MDName), result); err != nil {
				return err
			}
		case "html":
			if err := RenderHTML(filepath.Join(paths.Dir, paths.HTMLName), result); err != nil {
				return err
			}
		}
	}
	return nil
}
