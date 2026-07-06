package resolve_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/stretchr/testify/require"
)

func TestFetchLatestVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/lodash/latest", r.URL.Path)
		_, _ = w.Write([]byte(`{"version":"4.17.21"}`))
	}))
	defer srv.Close()

	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	ver, err := resolve.FetchLatestVersion(context.Background(), "lodash")
	require.NoError(t, err)
	require.Equal(t, "4.17.21", ver)
}

func TestFetchLatestVersionScoped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Contains(t, r.URL.Path, "@angular")
		_, _ = w.Write([]byte(`{"version":"19.0.0"}`))
	}))
	defer srv.Close()

	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	ver, err := resolve.FetchLatestVersion(context.Background(), "@angular/core")
	require.NoError(t, err)
	require.Equal(t, "19.0.0", ver)
}

func TestFetchVersionsScopedNotFoundIsPrivateRegistry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	_, err := resolve.FetchVersions(context.Background(), "@company/internal-auth")
	require.Error(t, err)
	var re *resolve.RegistryError
	require.ErrorAs(t, err, &re)
	require.Equal(t, resolve.ReasonPrivateRegistry, re.Reason)
}

func TestFetchVersionsUnscopedNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	_, err := resolve.FetchVersions(context.Background(), "totally-made-up-package")
	require.Error(t, err)
	var re *resolve.RegistryError
	require.ErrorAs(t, err, &re)
	require.Equal(t, resolve.ReasonNotFound, re.Reason)
}

func TestFetchVersionsAuthRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	_, err := resolve.FetchVersions(context.Background(), "@company/payment-sdk")
	require.Error(t, err)
	var re *resolve.RegistryError
	require.ErrorAs(t, err, &re)
	require.Equal(t, resolve.ReasonAuthRequired, re.Reason)
}

func TestResolvePackageLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"4.17.21"}`))
	}))
	defer srv.Close()

	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	comp, err := resolve.ResolvePackage(context.Background(), "lodash@latest")
	require.NoError(t, err)
	require.Equal(t, "lodash", comp.Name)
	require.Equal(t, "4.17.21", comp.Version)
}
