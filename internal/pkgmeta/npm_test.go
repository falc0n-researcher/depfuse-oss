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

	desc, license, home, err := pkgmeta.FetchRegistry(context.Background(), "express")
	require.NoError(t, err)
	require.Equal(t, "Fast, unopinionated, minimalist web framework", desc)
	require.Equal(t, "MIT", license)
	require.Equal(t, "https://expressjs.com", home)

	pkgmeta.SetHTTPClientForTest(dl.Client())
	counts, err := pkgmeta.FetchWeeklyDownloads(context.Background(), []string{"express"})
	require.NoError(t, err)
	require.Equal(t, int64(18_000_000), counts["express"])
}
