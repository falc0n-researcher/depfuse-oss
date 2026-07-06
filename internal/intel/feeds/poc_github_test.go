package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestPoCGitHubFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Contains(t, r.URL.RawQuery, "CVE-2025-29927")
		_, _ = w.Write([]byte(`{"items":[{"full_name":"user/CVE-2025-29927-poc","html_url":"https://github.com/user/poc","description":"PoC for CVE-2025-29927","stargazers_count":42,"fork":false}]}`))
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
	require.Equal(t, "user/CVE-2025-29927-poc", recs[0].Artifact.PoCRepo)
	require.NotNil(t, recs[0].Artifact.PoCStars)
	require.Equal(t, 42, *recs[0].Artifact.PoCStars)
	require.Equal(t, models.MaturityVerified, recs[0].Artifact.MaturityTag, "CVE-in-name + stars + description should corroborate to Verified")
}

func TestPoCGitHubStarsAloneDoNotVerify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"full_name":"user/generic-security-tools","html_url":"https://github.com/user/generic-security-tools","stargazers_count":500,"fork":false}]}`))
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
	require.Equal(t, models.MaturityHasCode, recs[0].Artifact.MaturityTag, "stars alone (no CVE-name match, no description) must not promote to Verified")
}

func TestPoCGitHubForksNeverVerify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"full_name":"user/CVE-2025-29927-poc","html_url":"https://github.com/user/poc","description":"PoC for CVE-2025-29927","stargazers_count":42,"fork":true}]}`))
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
	require.Equal(t, models.MaturityHasCode, recs[0].Artifact.MaturityTag, "a fork mirror must never be marked Verified regardless of signal count")
}

func TestPoCSignalCount(t *testing.T) {
	require.Equal(t, 1, pocSignalCount(ghRepo{Stars: 500}, "CVE-2025-29927"))
	require.Equal(t, 3, pocSignalCount(ghRepo{
		FullName: "user/CVE-2025-29927-poc", Description: "exploit", Stars: 11,
	}, "CVE-2025-29927"))
	require.Equal(t, 0, pocSignalCount(ghRepo{FullName: "user/unrelated"}, "CVE-2025-29927"))
}

func TestPoCGitHubDisabled(t *testing.T) {
	t.Setenv("DEPFUSE_POC_GITHUB", "0")
	f := &PoCGitHub{CVEs: []string{"CVE-2025-29927"}}
	recs, err := f.Fetch(context.Background(), "run-1")
	require.NoError(t, err)
	require.Nil(t, recs)
}
