package feeds

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestRecordsFromKEVEntries(t *testing.T) {
	entries := []vcKEVEntry{{
		Name: "Test vuln",
		CVE:  []string{"CVE-2024-4577"},
		VulnCheckReportedExploitation: []vcReportedExploit{
			{URL: "https://example.com/old", DateAdded: mustTime("2024-01-01T00:00:00Z")},
			{URL: "https://example.com/new", DateAdded: mustTime("2024-06-01T00:00:00Z")},
		},
		VulnCheckXDB: []vcXDB{{
			XDBID: "abc123", XDBURL: "https://vulncheck.com/xdb/abc123",
		}},
	}}
	recs := recordsFromKEVEntries(entries, "run-test")
	require.Len(t, recs, 4) // primary + 2 cites + xdb
}

func TestTopKEVCitationsCaps(t *testing.T) {
	var cites []vcReportedExploit
	for i := 0; i < 10; i++ {
		cites = append(cites, vcReportedExploit{URL: "https://example.com/" + string(rune('a'+i))})
	}
	top := topKEVCitations(cites, maxKEVCitationsPerCVE)
	require.Len(t, top, maxKEVCitationsPerCVE)
}

func TestVulnCheckKEVFetch(t *testing.T) {
	t.Setenv("DEPFUSE_VULNCHECK_TOKEN", "test-token")

	jsonPayload, err := json.Marshal([]vcKEVEntry{{
		Name: "PHP-CGI OS Command Injection Vulnerability",
		CVE:  []string{"CVE-2024-4577"},
		VulnCheckReportedExploitation: []vcReportedExploit{{
			URL: "https://isc.sans.edu/diary/example",
		}},
		VulnCheckXDB: []vcXDB{{
			XDBID: "024996c990cc", XDBURL: "https://vulncheck.com/xdb/024996c990cc",
		}},
	}})
	require.NoError(t, err)

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, err := zw.Create(kevJSONName)
	require.NoError(t, err)
	_, err = w.Write(jsonPayload)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	zipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipBuf.Bytes())
	}))
	defer zipSrv.Close()

	metaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(vcBackupResponse{Data: []vcBackupLink{{
			Filename: "vulncheck-kev.zip",
			URL:      zipSrv.URL,
		}}})
	}))
	defer metaSrv.Close()

	f := &KEV{BaseURL: metaSrv.URL}
	recs, err := f.Fetch(context.Background(), "run-test")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(recs), 3)

	var kev, xdb int
	for _, r := range recs {
		switch r.Artifact.Source {
		case models.SourceKEV:
			kev++
			require.Equal(t, "CVE-2024-4577", r.CanonicalID)
		case models.SourceVulnCheckXDB:
			xdb++
		}
	}
	require.Equal(t, 2, kev)
	require.Equal(t, 1, xdb)
}

func TestVulnCheckKEVRequiresToken(t *testing.T) {
	t.Setenv("DEPFUSE_VULNCHECK_TOKEN", "")
	f := &KEV{}
	_, err := f.Fetch(context.Background(), "run-test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "DEPFUSE_VULNCHECK_TOKEN")
}

func TestVulnCheckKEVLiveIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	token := strings.TrimSpace(os.Getenv("DEPFUSE_VULNCHECK_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("VULNCHECK_TOKEN"))
	}
	if token == "" {
		t.Skip("DEPFUSE_VULNCHECK_TOKEN not set")
	}
	t.Setenv("DEPFUSE_VULNCHECK_TOKEN", token)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	recs, err := (&KEV{}).Fetch(ctx, "live-test")
	require.NoError(t, err)
	require.Greater(t, len(recs), 10000)
}

func mustTime(s string) (t time.Time) {
	t, _ = time.Parse(time.RFC3339, s)
	return t
}
