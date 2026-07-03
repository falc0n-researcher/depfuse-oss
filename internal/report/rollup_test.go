package report

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestOutputPathsForPackageAndCVE(t *testing.T) {
	pkg := OutputPathsFor("", models.ScanResult{}, "express@4.17.1")
	require.Equal(t, "report-package.html", pkg.HTMLName)
	cve := OutputPathsFor("", models.ScanResult{Meta: models.ScanMeta{InputMode: models.InputModeCVE}}, "")
	require.Equal(t, "report-cve.html", cve.HTMLName)
}
