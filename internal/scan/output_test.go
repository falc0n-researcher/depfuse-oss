package scan_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/report"
	"github.com/falc0n-researcher/depfuse-oss/internal/scan"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestReportOutputDirDefaultsToHome(t *testing.T) {
	opts := scan.Options{Path: "."}
	result := models.ScanResult{Meta: models.ScanMeta{InputPath: "demo"}}
	paths := report.OutputPathsFor(opts.OutDir, result, opts.Package)
	require.Equal(t, intel.HomeDir(), paths.Dir)
	require.Equal(t, "report.html", paths.HTMLName)
}

func TestReportOutputPathsPackage(t *testing.T) {
	opts := scan.Options{Package: "express@4.17.1"}
	result := models.ScanResult{}
	paths := report.OutputPathsFor(opts.OutDir, result, opts.Package)
	require.Equal(t, "report-package.html", paths.HTMLName)
}

func TestReportOutputPathsCVE(t *testing.T) {
	result := models.ScanResult{Meta: models.ScanMeta{InputMode: models.InputModeCVE}}
	paths := report.OutputPathsFor("", result, "")
	require.Equal(t, "report-cve.html", paths.HTMLName)
}

func TestReportOutputDirOverride(t *testing.T) {
	opts := scan.Options{OutDir: "/tmp/custom"}
	result := models.ScanResult{}
	paths := report.OutputPathsFor(opts.OutDir, result, opts.Package)
	require.Equal(t, "/tmp/custom", paths.Dir)
}
