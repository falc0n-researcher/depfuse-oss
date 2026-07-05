package scan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRenderShadowDepsSkipsPackageModeByDefault(t *testing.T) {
	var buf bytes.Buffer
	components := []models.Component{
		{Name: "express", Version: "4.17.1", Direct: true, Path: []string{"express"}},
		{Name: "qs", Version: "6.7.0", Path: []string{"express", "qs"}},
	}
	opts := Options{Package: "express@4.17.1"}
	result := models.ScanResult{Components: components}

	renderShadowDeps(&buf, opts, result)

	require.NotContains(t, buf.String(), "Shadow Dependencies")
	require.NotContains(t, buf.String(), "--tree")
}

func TestRenderShadowDepsScanModeShowsTreeHint(t *testing.T) {
	var buf bytes.Buffer
	components := []models.Component{
		{Name: "express", Version: "4.17.1", Direct: true, Path: []string{"express"}},
		{Name: "qs", Version: "6.7.0", Path: []string{"express", "qs"}},
	}
	opts := Options{Path: "."}
	result := models.ScanResult{Components: components}

	renderShadowDeps(&buf, opts, result)

	out := buf.String()
	require.Contains(t, out, "Shadow Dependencies")
	require.Contains(t, out, "--tree")
}

func TestRenderShadowDepsPackageWithTreeFlag(t *testing.T) {
	var buf bytes.Buffer
	components := []models.Component{
		{Name: "express", Version: "4.17.1", Direct: true, Path: []string{"express"}},
		{Name: "qs", Version: "6.7.0", Path: []string{"express", "qs"}},
	}
	opts := Options{Package: "express@4.17.1", ShowTree: true}
	result := models.ScanResult{Components: components, ShowTree: true}

	renderShadowDeps(&buf, opts, result)

	out := buf.String()
	require.Contains(t, out, "Shadow Dependencies")
	require.NotContains(t, out, "Use --tree")
	require.True(t, strings.Contains(out, "express@4.17.1") || strings.Contains(out, "express"))
}
