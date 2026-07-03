package lockfile_test

import (
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
