package resolve_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestNormalizeScanRootDirectory(t *testing.T) {
	dir := t.TempDir()
	root, err := resolve.NormalizeScanRoot(dir)
	require.NoError(t, err)
	require.Equal(t, dir, root)
}

func TestNormalizeScanRootPackageJSONFile(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(manifest, []byte(`{"name":"app"}`), 0o644))

	root, err := resolve.NormalizeScanRoot(manifest)
	require.NoError(t, err)
	require.Equal(t, dir, root)
}

func TestNormalizeScanRootRejectsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "README.md")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	_, err := resolve.NormalizeScanRoot(file)
	require.Error(t, err)
}

func TestUsesManifestOnlyResolution(t *testing.T) {
	require.True(t, resolve.UsesManifestOnlyResolution([]models.Component{
		{Name: "lodash", Version: "4.17.21", Spec: "^4.17.0"},
	}))
	require.False(t, resolve.UsesManifestOnlyResolution([]models.Component{
		{Name: "lodash", Version: "4.17.21"},
	}))
}
