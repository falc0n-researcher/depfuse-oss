package pkgmeta_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/stretchr/testify/require"
)

func TestFetchRegistryAndDownloads(t *testing.T) {
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/express":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":        "express",
				"description": "Fast, unopinionated, minimalist web framework",
				"license":     "MIT",
				"homepage":    "https://expressjs.com",
				"dist-tags":   map[string]any{"latest": "4.19.2"},
				"versions": map[string]any{
					"4.19.2": map[string]any{
						"scripts": map[string]any{"postinstall": "node build.js"},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer reg.Close()

	dl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"package": "express", "downloads": float64(18_000_000),
		}})
	}))
	defer dl.Close()

	t.Cleanup(func() {
		pkgmeta.SetRegistryURLForTest("https://registry.npmjs.org")
		pkgmeta.SetHTTPClientForTest(nil)
		pkgmeta.SetDownloadsURLForTest("https://api.npmjs.org/downloads/point/last-week")
	})
	pkgmeta.SetRegistryURLForTest(reg.URL)
	pkgmeta.SetDownloadsURLForTest(dl.URL)
	pkgmeta.SetHTTPClientForTest(reg.Client())

	desc, license, home, scripts, err := pkgmeta.FetchRegistry(context.Background(), "express")
	require.NoError(t, err)
	require.Equal(t, "Fast, unopinionated, minimalist web framework", desc)
	require.Equal(t, "MIT", license)
	require.Equal(t, "https://expressjs.com", home)
	require.Equal(t, []string{"postinstall"}, scripts)

	pkgmeta.SetHTTPClientForTest(dl.Client())
	counts, err := pkgmeta.FetchWeeklyDownloads(context.Background(), []string{"express"})
	require.NoError(t, err)
	require.Equal(t, int64(18_000_000), counts["express"])
}

func TestFetchRegistryNoLifecycleScripts(t *testing.T) {
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      "lodash",
			"dist-tags": map[string]any{"latest": "4.17.21"},
			"versions": map[string]any{
				"4.17.21": map[string]any{"scripts": map[string]any{"test": "mocha"}},
			},
		})
	}))
	defer reg.Close()

	t.Cleanup(func() {
		pkgmeta.SetRegistryURLForTest("https://registry.npmjs.org")
		pkgmeta.SetHTTPClientForTest(nil)
	})
	pkgmeta.SetRegistryURLForTest(reg.URL)
	pkgmeta.SetHTTPClientForTest(reg.Client())

	_, _, _, scripts, err := pkgmeta.FetchRegistry(context.Background(), "lodash")
	require.NoError(t, err)
	require.Empty(t, scripts, "non-lifecycle scripts (test, build, etc.) must not be surfaced")
}

func TestFetchRegistryMultipleLifecycleScripts(t *testing.T) {
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      "node-gyp-example",
			"dist-tags": map[string]any{"latest": "1.0.0"},
			"versions": map[string]any{
				"1.0.0": map[string]any{"scripts": map[string]any{
					"preinstall": "node check.js", "postinstall": "node-gyp rebuild", "test": "jest",
				}},
			},
		})
	}))
	defer reg.Close()

	t.Cleanup(func() {
		pkgmeta.SetRegistryURLForTest("https://registry.npmjs.org")
		pkgmeta.SetHTTPClientForTest(nil)
	})
	pkgmeta.SetRegistryURLForTest(reg.URL)
	pkgmeta.SetHTTPClientForTest(reg.Client())

	_, _, _, scripts, err := pkgmeta.FetchRegistry(context.Background(), "node-gyp-example")
	require.NoError(t, err)
	require.Equal(t, []string{"preinstall", "postinstall"}, scripts)
}
