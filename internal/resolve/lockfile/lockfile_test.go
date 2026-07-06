package lockfile_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve/lockfile"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func testdataPath(t *testing.T, parts ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	base := filepath.Join(filepath.Dir(file), "..", "..", "..", "testdata")
	return filepath.Join(append([]string{base}, parts...)...)
}

func TestNPMTransitiveDependencyPath(t *testing.T) {
	manifest := testdataPath(t, "express-app", "package.json")
	lock := testdataPath(t, "express-app", "package-lock.json")
	deps, err := lockfile.LoadManifestDeps(manifest)
	require.NoError(t, err)

	comps, err := lockfile.ParseNPM(manifest, deps, lock)
	require.NoError(t, err)

	paths := map[string][]string{}
	for _, c := range comps {
		if c.Name == "qs" {
			paths["qs"] = c.Path
		}
	}
	require.Equal(t, []string{"express", "qs"}, paths["qs"])
}

func TestNPMDirectDependencyPath(t *testing.T) {
	manifest := testdataPath(t, "express-app", "package.json")
	lock := testdataPath(t, "express-app", "package-lock.json")
	deps, err := lockfile.LoadManifestDeps(manifest)
	require.NoError(t, err)

	comps, err := lockfile.ParseNPM(manifest, deps, lock)
	require.NoError(t, err)

	for _, c := range comps {
		if c.Name == "express" {
			require.Equal(t, []string{"express"}, c.Path)
			return
		}
	}
	t.Fatal("express not found")
}

func TestNPMPathConfidenceIsExact(t *testing.T) {
	manifest := testdataPath(t, "express-app", "package.json")
	lock := testdataPath(t, "express-app", "package-lock.json")
	deps, err := lockfile.LoadManifestDeps(manifest)
	require.NoError(t, err)

	comps, err := lockfile.ParseNPM(manifest, deps, lock)
	require.NoError(t, err)
	require.NotEmpty(t, comps)
	for _, c := range comps {
		require.Equal(t, lockfile.PathConfidenceExact, c.PathConfidence)
	}
}

const pnpmLockV6 = `lockfileVersion: '6.0'

packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-abc=}
    engines: {node: '>=0.10.0'}
`

const pnpmLockV9 = `lockfileVersion: '9.0'

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-abc=}
    engines: {node: '>=0.10.0'}

snapshots:
  lodash@4.17.21: {}
`

func writeTempLockfile(t *testing.T, name, content string) (manifest, lock string) {
	t.Helper()
	dir := t.TempDir()
	manifest = filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(manifest, []byte(`{"name":"app","dependencies":{"lodash":"^4.17.21"}}`), 0o644))
	lock = filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(lock, []byte(content), 0o644))
	return manifest, lock
}

func TestParsePNPMLockfileVersion6(t *testing.T) {
	manifest, lock := writeTempLockfile(t, "pnpm-lock.yaml", pnpmLockV6)
	deps, err := lockfile.LoadManifestDeps(manifest)
	require.NoError(t, err)

	comps, err := lockfile.ParsePNPM(manifest, deps, lock)
	require.NoError(t, err)
	require.Len(t, comps, 1)
	require.Equal(t, "lodash", comps[0].Name)
	require.Equal(t, "4.17.21", comps[0].Version)
	require.Equal(t, lockfile.PathConfidenceLow, comps[0].PathConfidence)
}

func TestParsePNPMLockfileVersion9NoLeadingSlash(t *testing.T) {
	manifest, lock := writeTempLockfile(t, "pnpm-lock.yaml", pnpmLockV9)
	deps, err := lockfile.LoadManifestDeps(manifest)
	require.NoError(t, err)

	comps, err := lockfile.ParsePNPM(manifest, deps, lock)
	require.NoError(t, err)
	require.Len(t, comps, 1, "pnpm lockfileVersion 9 packages: keys have no leading slash and must still parse")
	require.Equal(t, "lodash", comps[0].Name)
	require.Equal(t, "4.17.21", comps[0].Version)
}

const yarnLockV1 = `# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
`

func TestParseYarnPathConfidenceIsLow(t *testing.T) {
	manifest, lock := writeTempLockfile(t, "yarn.lock", yarnLockV1)
	deps, err := lockfile.LoadManifestDeps(manifest)
	require.NoError(t, err)

	comps, err := lockfile.ParseYarn(manifest, deps, lock)
	require.NoError(t, err)
	require.Len(t, comps, 1)
	require.Equal(t, lockfile.PathConfidenceLow, comps[0].PathConfidence)
	require.Equal(t, []string{"lodash"}, comps[0].Path)
}

func TestParseManifestOnlySpecs(t *testing.T) {
	deps := lockfile.ManifestDeps{
		Prod:  map[string]bool{"lodash": true, "next": true},
		Dev:   map[string]bool{},
		Specs: map[string]string{"lodash": "4.17.20", "next": "^13.0.0"},
	}
	comps, err := lockfile.ParseManifestOnly("/tmp/package.json", deps)
	require.NoError(t, err)
	byName := map[string]models.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// Exact spec is pinned immediately.
	require.Equal(t, "4.17.20", byName["lodash"].Version)
	require.False(t, byName["lodash"].Unresolved)
	// Range spec stays unresolved with the raw spec preserved for the caller.
	require.True(t, byName["next"].Unresolved)
	require.Equal(t, "^13.0.0", byName["next"].Spec)
}
