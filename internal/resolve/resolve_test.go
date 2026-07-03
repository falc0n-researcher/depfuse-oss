package resolve_test

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func testdataPath(t *testing.T, parts ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	base := filepath.Join(filepath.Dir(file), "..", "..", "testdata")
	return filepath.Join(append([]string{base}, parts...)...)
}

func TestResolveExpressApp(t *testing.T) {
	root := testdataPath(t, "express-app")
	comps, err := resolve.Resolve(resolve.Options{Root: root})
	require.NoError(t, err)
	require.NotEmpty(t, comps)

	names := map[string]models.Component{}
	for _, c := range comps {
		names[c.Name] = c
	}
	require.Equal(t, "4.17.1", names["express"].Version)
	require.Equal(t, models.ScopeProd, names["express"].Scope)
	require.True(t, names["express"].Direct)
	require.Equal(t, models.ScopeDev, names["eslint"].Scope)
}

func TestResolvePackage(t *testing.T) {
	comp, err := resolve.ResolvePackage(context.Background(), "lodash@4.17.21")
	require.NoError(t, err)
	require.Equal(t, "lodash", comp.Name)
	require.Equal(t, "4.17.21", comp.Version)
}
