package lockfile_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve/lockfile"
	"github.com/stretchr/testify/require"
)

func TestParseYarnBerryLock(t *testing.T) {
	manifest := testdataPath(t, "yarn-berry-app", "package.json")
	lock := testdataPath(t, "yarn-berry-app", "yarn.lock")
	deps, err := lockfile.LoadManifestDeps(manifest)
	require.NoError(t, err)

	comps, err := lockfile.ParseYarn(manifest, deps, lock)
	require.NoError(t, err)

	var lodash string
	for _, c := range comps {
		if c.Name == "lodash" {
			lodash = c.Version
		}
	}
	require.Equal(t, "4.17.21", lodash)
}

func TestParseBunLock(t *testing.T) {
	manifest := testdataPath(t, "bun-app", "package.json")
	lock := testdataPath(t, "bun-app", "bun.lock")
	deps, err := lockfile.LoadManifestDeps(manifest)
	require.NoError(t, err)

	comps, err := lockfile.ParseBun(manifest, deps, lock)
	require.NoError(t, err)

	var lodash string
	for _, c := range comps {
		if c.Name == "lodash" {
			lodash = c.Version
		}
	}
	require.Equal(t, "4.17.21", lodash)
}

func TestParseBunPackageKeyScoped(t *testing.T) {
	manifest := testdataPath(t, "bun-app", "package.json")
	lock := testdataPath(t, "bun-app", "bun.lock")
	deps, err := lockfile.LoadManifestDeps(manifest)
	require.NoError(t, err)
	_, err = lockfile.ParseBun(manifest, deps, lock)
	require.NoError(t, err)
}
