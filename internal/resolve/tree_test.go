package resolve_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestResolvePackageTreeTransitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/parent/latest":
			_, _ = w.Write([]byte(`{"version":"1.0.0"}`))
		case "/parent/1.0.0":
			_ = json.NewEncoder(w).Encode(resolve.VersionManifest{
				Dependencies: map[string]string{"child": "^2.0.0"},
			})
		case "/child":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"versions": map[string]any{"2.0.0": map[string]any{}},
			})
		case "/child/2.0.0":
			_ = json.NewEncoder(w).Encode(resolve.VersionManifest{
				Dependencies: map[string]string{"leaf": "3.0.0"},
			})
		case "/leaf":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"versions": map[string]any{"3.0.0": map[string]any{}},
			})
		case "/leaf/3.0.0":
			_ = json.NewEncoder(w).Encode(resolve.VersionManifest{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("DEPFUSE_TREE_CACHE", t.TempDir())
	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	comps, stats, err := resolve.ResolvePackageTree(context.Background(), "parent@1.0.0", resolve.TreeOptions{})
	require.NoError(t, err)
	require.Equal(t, 3, stats.Total)
	require.Equal(t, 1, stats.Direct)
	require.Equal(t, 2, stats.Transitive)
	require.Equal(t, "parent@1.0.0", stats.Root)

	byName := indexComponents(comps)
	require.Contains(t, byName, "leaf@3.0.0")
	require.Equal(t, []string{"parent", "child", "leaf"}, byName["leaf@3.0.0"].Path)
}

func TestResolvePackageTreeDepthOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"1.0.0"}`))
	}))
	defer srv.Close()
	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	comps, stats, err := resolve.ResolvePackageTree(context.Background(), "solo@latest", resolve.TreeOptions{Depth: 1})
	require.NoError(t, err)
	require.Len(t, comps, 1)
	require.Equal(t, 1, stats.Total)
}

func TestResolvePackageTreeCacheRoundTrip(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/cached/1.0.0":
			if r.Method == http.MethodGet && r.URL.Path == "/cached/1.0.0" {
				_ = json.NewEncoder(w).Encode(resolve.VersionManifest{
					Dependencies: map[string]string{"dep": "1.0.0"},
				})
				return
			}
		case "/dep":
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": map[string]any{"1.0.0": map[string]any{}}})
		case "/dep/1.0.0":
			_ = json.NewEncoder(w).Encode(resolve.VersionManifest{})
		}
	}))
	defer srv.Close()

	t.Setenv("DEPFUSE_TREE_CACHE", filepath.Join(t.TempDir(), "deptree"))
	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	opts := resolve.TreeOptions{}
	_, _, err := resolve.ResolvePackageTree(context.Background(), "cached@1.0.0", opts)
	require.NoError(t, err)
	firstCalls := calls

	_, _, err = resolve.ResolvePackageTree(context.Background(), "cached@1.0.0", opts)
	require.NoError(t, err)
	require.Equal(t, firstCalls, calls, "second resolve should hit tree cache")
}

func TestFormatDependencyPath(t *testing.T) {
	path := resolve.FormatDependencyPath(models.Component{
		Name: "qs", Path: []string{"express", "body-parser"},
	})
	require.Equal(t, "express → body-parser → qs", path)
}

func indexComponents(comps []models.Component) map[string]models.Component {
	out := make(map[string]models.Component, len(comps))
	for _, c := range comps {
		out[c.Name+"@"+c.Version] = c
	}
	return out
}
