package intel_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestAbortRunningFeedRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	defer s.Close()

	require.NoError(t, s.EnsureFeeds())
	require.NoError(t, s.BeginFeedRun("run-1", "KEV"))

	n, err := s.AbortRunningFeedRuns("test abort")
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	var status string
	err = s.DB().QueryRow(`SELECT status FROM feed_runs WHERE id='run-1'`).Scan(&status)
	require.NoError(t, err)
	require.Equal(t, "aborted", status)
}

func TestEnrichVulnRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vulns/CVE-2026-33032":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "CVE-2026-33032",
				"summary":   "Test advisory summary",
				"published": "2026-01-01T00:00:00Z",
				"aliases":   []string{"GHSA-h6c2-x2m2-mwhf", "GO-2026-4904"},
				"affected": []map[string]any{
					{"ranges": []map[string]any{{"events": []map[string]string{{"fixed": "1.2.3"}}}}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	defer s.Close()

	now := time.Now().UTC()
	require.NoError(t, s.UpsertNormalizedRecord(intel.NormalizedRecord{
		CanonicalID: "CVE-2026-33032",
		Artifact: intel.ArtifactInput{
			ID: "KEV:CVE-2026-33032", Source: models.SourceKEV, TrustClass: models.TrustAuthoritative,
			Title: "test", ObservedAt: now,
		},
	}))

	synced, err := intel.EnrichVulnRecordsWithBaseURL(context.Background(), s, srv.URL+"/v1/vulns/", []string{"CVE-2026-33032"})
	require.NoError(t, err)
	require.Equal(t, 1, synced)

	var ghsaCount int
	err = s.DB().QueryRow(`SELECT COUNT(*) FROM vuln_aliases WHERE alias_type='GHSA'`).Scan(&ghsaCount)
	require.NoError(t, err)
	require.Equal(t, 1, ghsaCount)

	arts, err := s.ArtifactsForAnyID("GHSA-h6c2-x2m2-mwhf")
	require.NoError(t, err)
	require.NotEmpty(t, arts)

	cm := models.CveMatch{CVEID: "CVE-2026-33032"}
	require.NoError(t, intel.EnrichCveMatch(context.Background(), s, &cm, true))
	require.Equal(t, "Test advisory summary", cm.Summary)
	require.Contains(t, cm.FixedVersions, "1.2.3")
}

func TestEnrichCveMatchFromCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/v1/vulns/") {
		case "GHSA-f82v-jwr5-mffw":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        "GHSA-f82v-jwr5-mffw",
				"summary":   "Authorization Bypass in Next.js Middleware",
				"published": "2025-03-01T00:00:00Z",
				"aliases":   []string{"CVE-2025-29927"},
				"severity":  []map[string]string{{"type": "CVSS_V3", "score": "9.1"}},
				"affected": []map[string]any{
					{
						"package": map[string]string{"name": "next", "ecosystem": "npm"},
						"ranges":  []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"introduced": "15.0.0"}, {"fixed": "15.2.3"}}}},
					},
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "CVE-2025-29927",
				"summary": "Authorization Bypass in Next.js Middleware",
				"aliases": []string{"GHSA-f82v-jwr5-mffw"},
				"affected": []map[string]any{
					{"ranges": []map[string]any{{"type": "GIT", "events": []map[string]string{{"fixed": "6687ab55a362f1fe8cb15a76640cc87ff90d15f2"}}}}},
				},
			})
		}
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	defer s.Close()

	_, err = intel.EnrichVulnRecordsWithBaseURL(context.Background(), s, srv.URL+"/v1/vulns/", []string{"CVE-2025-29927", "GHSA-f82v-jwr5-mffw"})
	require.NoError(t, err)

	cm := models.CveMatch{CVEID: "CVE-2025-29927", OSVID: "CVE-2025-29927", GHSAID: "GHSA-f82v-jwr5-mffw"}
	require.NoError(t, intel.EnrichCveMatch(context.Background(), s, &cm, true))
	require.Equal(t, "Authorization Bypass in Next.js Middleware", cm.Summary)
	require.Contains(t, cm.FixedVersions, "15.2.3")
}
