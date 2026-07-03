package match_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/match"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestFormatUnaffectedPackageNote(t *testing.T) {
	comp := models.Component{Name: "@theia/debug", Version: "1.72.3"}
	catalog := []models.CveMatch{{
		GHSAID: "GHSA-g9jw-92q7-g7fj", CVEID: "GHSA-g9jw-92q7-g7fj",
		FixedVersions: []string{"1.69.0"},
	}}
	note := match.FormatUnaffectedPackageNote(comp, catalog)
	require.Contains(t, note, "GHSA-g9jw-92q7-g7fj")
	require.Contains(t, note, "1.72.3")
	require.Contains(t, note, "1.69.0")
	require.Contains(t, note, "depfuse package")
}

func TestQueryPackageCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{
				"id": "GHSA-g9jw-92q7-g7fj", "summary": "Theia RCE",
				"affected": []map[string]any{{
					"package": map[string]string{"name": "@theia/debug", "ecosystem": "npm"},
					"ranges":  []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"fixed": "1.69.0"}}}},
				}},
			}},
		})
	}))
	defer srv.Close()
	match.SetOSVBatchURLForTest(srv.URL)
	oldQuery := match.OSVQueryURLForTest()
	match.SetOSVQueryURLForTest(srv.URL)
	t.Cleanup(func() {
		match.SetOSVQueryURLForTest(oldQuery)
		match.SetOSVBatchURLForTest("https://api.osv.dev/v1/querybatch")
	})

	client := &match.Client{HTTP: srv.Client()}
	out, err := client.QueryPackageCatalog(context.Background(), "@theia/debug")
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, "GHSA-g9jw-92q7-g7fj", out[0].AdvisoryID())
}

func TestCanonicalCVE(t *testing.T) {
	require.Equal(t, "CVE-2021-44228", match.CanonicalCVE("GHSA-jfh8-c2jp-5v3q", []string{"CVE-2021-44228"}))
	require.Equal(t, "CVE-2021-44228", match.CanonicalCVE("CVE-2021-44228", nil))
	require.Equal(t, "", match.CanonicalCVE("GHSA-xxxx-yyyy-zzzz", nil))
}

func TestMatchComponentsDedupesQueries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			Queries []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
			} `json:"queries"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Len(t, req.Queries, 1)
		require.Equal(t, "lodash", req.Queries[0].Package.Name)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{{"vulns": []any{}}},
		})
	}))
	defer srv.Close()

	t.Setenv("DEPFUSE_OSV_BATCH_SIZE", "100")

	match.SetOSVBatchURLForTest(srv.URL)
	t.Cleanup(func() { match.SetOSVBatchURLForTest("https://api.osv.dev/v1/querybatch") })

	client := &match.Client{HTTP: srv.Client()}
	comps := []models.Component{
		{Name: "lodash", Version: "4.17.21"},
		{Name: "lodash", Version: "4.17.21"},
	}
	out, err := client.MatchComponents(context.Background(), comps)
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Equal(t, int32(1), calls.Load())
	require.Equal(t, 1, client.Stats.OSVQueries)
}

func TestMatchComponentsRetriesOn429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`rate limited`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{{"vulns": []any{}}},
		})
	}))
	defer srv.Close()

	match.SetOSVBatchURLForTest(srv.URL)
	t.Cleanup(func() { match.SetOSVBatchURLForTest("https://api.osv.dev/v1/querybatch") })

	client := &match.Client{HTTP: srv.Client()}
	_, err := client.MatchComponents(context.Background(), []models.Component{
		{Name: "express", Version: "4.17.1"},
	})
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load())
}

func TestMatchComponentsCacheFirst(t *testing.T) {
	db := &fakeOfflineDB{
		data: map[string][]models.CveMatch{
			"lodash@4.17.21": {{CVEID: "CVE-TEST-0001"}},
		},
	}
	client := &match.Client{OfflineDB: db}
	out, err := client.MatchComponents(context.Background(), []models.Component{
		{Name: "lodash", Version: "4.17.21"},
	})
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, "CVE-TEST-0001", out[0].Matches[0].CVEID)
	require.Equal(t, 1, client.Stats.OSVCacheHits)
	require.Equal(t, 0, client.Stats.OSVQueries)
}

type fakeOfflineDB struct {
	data map[string][]models.CveMatch
}

func (f *fakeOfflineDB) GetOSVMatches(ecosystem, name, version string) ([]models.CveMatch, bool) {
	m, ok := f.data[name+"@"+version]
	return m, ok
}
