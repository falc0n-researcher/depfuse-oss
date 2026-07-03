package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPoCGitHubFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Contains(t, r.URL.RawQuery, "CVE-2025-29927")
		_, _ = w.Write([]byte(`{"items":[{"full_name":"user/poc","html_url":"https://github.com/user/poc","stargazers_count":42}]}`))
	}))
	defer srv.Close()

	t.Setenv("GITHUB_TOKEN", "test-token")
	old := githubSearchBaseURL
	githubSearchBaseURL = srv.URL
	t.Cleanup(func() { githubSearchBaseURL = old })

	f := &PoCGitHub{CVEs: []string{"CVE-2025-29927"}}
	recs, err := f.Fetch(context.Background(), "run-1")
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.Equal(t, "user/poc", recs[0].Artifact.PoCRepo)
	require.NotNil(t, recs[0].Artifact.PoCStars)
	require.Equal(t, 42, *recs[0].Artifact.PoCStars)
}

func TestPoCGitHubDisabled(t *testing.T) {
	t.Setenv("DEPFUSE_POC_GITHUB", "0")
	f := &PoCGitHub{CVEs: []string{"CVE-2025-29927"}}
	recs, err := f.Fetch(context.Background(), "run-1")
	require.NoError(t, err)
	require.Nil(t, recs)
}
