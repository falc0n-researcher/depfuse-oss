package resolve_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/stretchr/testify/require"
)

func TestNormalizeNPMPackageNameScoped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/@budibase/server":
			w.WriteHeader(http.StatusOK)
		case "/budibase/server":
			w.WriteHeader(http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	got := resolve.NormalizeNPMPackageName(context.Background(), "budibase/server")
	require.Equal(t, "@budibase/server", got)
}

func TestResolvePackageScopedAlias(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/@budibase/server":
			w.WriteHeader(http.StatusOK)
		case "/budibase/server":
			w.WriteHeader(http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	resolve.SetNPMRegistryURLForTest(srv.URL)
	t.Cleanup(func() { resolve.SetNPMRegistryURLForTest("https://registry.npmjs.org") })

	comp, err := resolve.ResolvePackage(context.Background(), "budibase/server@3.39.0")
	require.NoError(t, err)
	require.Equal(t, "@budibase/server", comp.Name)
	require.Equal(t, "3.39.0", comp.Version)
}
