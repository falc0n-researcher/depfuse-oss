package resolve_test

import (
	"net/http"
	"net/http/httptest"
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

func TestUnresolvedComponentsCarryReason(t *testing.T) {
	comps := []models.Component{
		{Name: "lodash", Version: "4.17.21"},
		{Name: "@company/internal-auth", Version: "*", Spec: "^1.0.0", Unresolved: true, UnresolvedReason: resolve.ReasonPrivateRegistry},
	}
	unresolved := resolve.UnresolvedComponents(comps)
	require.Len(t, unresolved, 1)
	require.Equal(t, "@company/internal-auth", unresolved[0].Name)
	require.Equal(t, resolve.ReasonPrivateRegistry, unresolved[0].UnresolvedReason)
}

func TestResolveManifestOnlyScopedPackageGetsPrivateRegistryReason(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(manifest, []byte(`{"name":"app","dependencies":{"@company/internal-auth":"^1.0.0"}}`), 0o644))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	comps, err := resolve.Resolve(resolve.Options{Root: dir})
	require.NoError(t, err)

	unresolved := resolve.UnresolvedComponents(comps)
	require.Len(t, unresolved, 1)
	require.Equal(t, "@company/internal-auth", unresolved[0].Name)
	require.Equal(t, resolve.ReasonPrivateRegistry, unresolved[0].UnresolvedReason)
}

func TestResolveManifestOnlyOfflineGetsOfflineReason(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(manifest, []byte(`{"name":"app","dependencies":{"lodash":"^4.17.0"}}`), 0o644))

	comps, err := resolve.Resolve(resolve.Options{Root: dir, Offline: true})
	require.NoError(t, err)

	unresolved := resolve.UnresolvedComponents(comps)
	require.Len(t, unresolved, 1)
	require.Equal(t, resolve.ReasonOfflineMode, unresolved[0].UnresolvedReason)
}
