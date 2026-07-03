package resolve_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/resolve"
	"github.com/stretchr/testify/require"
)

func TestGoldenResolveMonorepoYarn(t *testing.T) {
	root := testdataPath(t, "monorepo-yarn")
	comps, err := resolve.Resolve(resolve.Options{Root: root})
	require.NoError(t, err)

	var lodash string
	for _, c := range comps {
		if c.Name == "lodash" {
			lodash = c.Version
		}
	}
	require.Equal(t, "4.17.21", lodash)
}

func TestGoldenResolveMonorepoPnpm(t *testing.T) {
	root := testdataPath(t, "monorepo-pnpm")
	comps, err := resolve.Resolve(resolve.Options{Root: root})
	require.NoError(t, err)

	var lodash string
	for _, c := range comps {
		if c.Name == "lodash" {
			lodash = c.Version
		}
	}
	require.Equal(t, "4.17.21", lodash)
}

func TestGoldenResolveNextApp(t *testing.T) {
	root := testdataPath(t, "next-app")
	comps, err := resolve.Resolve(resolve.Options{Root: root})
	require.NoError(t, err)

	var nextVer string
	for _, c := range comps {
		if c.Name == "next" {
			nextVer = c.Version
		}
	}
	require.Equal(t, "15.1.0", nextVer)
}

func TestGoldenResolveYarnBerry(t *testing.T) {
	root := testdataPath(t, "yarn-berry-app")
	comps, err := resolve.Resolve(resolve.Options{Root: root})
	require.NoError(t, err)

	var lodash string
	for _, c := range comps {
		if c.Name == "lodash" {
			lodash = c.Version
		}
	}
	require.Equal(t, "4.17.21", lodash)
}

func TestGoldenResolveBun(t *testing.T) {
	root := testdataPath(t, "bun-app")
	comps, err := resolve.Resolve(resolve.Options{Root: root})
	require.NoError(t, err)

	var lodash string
	for _, c := range comps {
		if c.Name == "lodash" {
			lodash = c.Version
		}
	}
	require.Equal(t, "4.17.21", lodash)
}
