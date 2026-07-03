package resolve_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/stretchr/testify/require"
)

func TestDiscoverWorkspacesArray(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(manifest, []byte(`{
  "name": "root",
  "workspaces": ["packages/*", "apps/*"]
}`), 0o644))

	patterns, err := resolve.DiscoverWorkspaces(manifest)
	require.NoError(t, err)
	require.Equal(t, []string{"packages/*", "apps/*"}, patterns)
}

func TestDiscoverWorkspacesObject(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(manifest, []byte(`{
  "name": "root",
  "workspaces": { "packages": ["packages/*"] }
}`), 0o644))

	patterns, err := resolve.DiscoverWorkspaces(manifest)
	require.NoError(t, err)
	require.Equal(t, []string{"packages/*"}, patterns)
}

func TestExpandWorkspaceGlobs(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "api"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "web"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "packages", "api", "package.json"), []byte(`{"name":"api"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "packages", "web", "package.json"), []byte(`{"name":"web"}`), 0o644))

	paths, err := resolve.ExpandWorkspaceGlobs(root, []string{"packages/*"})
	require.NoError(t, err)
	require.Len(t, paths, 2)
}

func TestResolveMonorepoInheritsRootLockfile(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "packages", "api")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name": "monorepo-root",
  "workspaces": ["packages/*"]
}`), 0o644))

	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{
  "name": "api",
  "dependencies": { "lodash": "^4.17.21" }
}`), 0o644))

	require.NoError(t, os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{
  "name": "monorepo-root",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "monorepo-root" },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`), 0o644))

	comps, err := resolve.Resolve(resolve.Options{Root: root})
	require.NoError(t, err)

	found := false
	for _, c := range comps {
		if c.Name == "lodash" {
			found = true
			require.Equal(t, "4.17.21", c.Version, "workspace should inherit root lockfile version, not *")
			require.True(t, c.Direct)
		}
	}
	require.True(t, found, "lodash from root lockfile should be resolved")
}

func TestResolveMonorepoFixture(t *testing.T) {
	root := testdataPath(t, "monorepo-npm")
	comps, err := resolve.Resolve(resolve.Options{Root: root})
	require.NoError(t, err)

	var lodash string
	for _, c := range comps {
		if c.Name == "lodash" {
			lodash = c.Version
		}
	}
	require.Equal(t, "4.17.21", lodash)
}

func TestFindLockfileWalksUp(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "packages", "api")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	lock := filepath.Join(root, "package-lock.json")
	require.NoError(t, os.WriteFile(lock, []byte(`{"lockfileVersion":3,"packages":{}}`), 0o644))

	kind, path := resolve.FindLockfile(nested, root)
	require.Equal(t, "npm", kind)
	require.Equal(t, lock, path)
}
