package intel_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestEnrichCveMatchAffectedPackages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":        "GHSA-g9jw-92q7-g7fj",
			"summary":   "Arbitrary Command Execution via Untrusted Workspace Task Definitions",
			"published": "2026-06-18T00:00:00Z",
			"aliases":   []string{"CVE-2026-44691"},
			"affected": []map[string]any{
				{
					"package": map[string]string{"name": "@theia/debug", "ecosystem": "npm"},
					"ranges":  []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"fixed": "1.69.0"}}}},
				},
				{
					"package": map[string]string{"name": "@theia/task", "ecosystem": "npm"},
					"ranges":  []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"fixed": "1.69.0"}}}},
				},
				{
					"package": map[string]string{"name": "@theia/workspace", "ecosystem": "npm"},
					"ranges":  []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"fixed": "1.69.0"}}}},
				},
			},
		})
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	defer s.Close()

	_, err = intel.EnrichVulnRecordsWithBaseURL(context.Background(), s, srv.URL+"/v1/vulns/", []string{"CVE-2026-44691"})
	require.NoError(t, err)

	cm := models.CveMatch{CVEID: "CVE-2026-44691"}
	require.NoError(t, intel.EnrichCveMatch(context.Background(), s, &cm, true))

	pkgs := cm.NPMAffectedPackages()
	require.Len(t, pkgs, 3)
	require.Equal(t, "@theia/debug", pkgs[0].Name)
	require.Equal(t, "@theia/task", pkgs[1].Name)
	require.Equal(t, "@theia/workspace", pkgs[2].Name)
	for _, p := range pkgs {
		require.Equal(t, "1.69.0", p.FixedVersion)
	}
}
