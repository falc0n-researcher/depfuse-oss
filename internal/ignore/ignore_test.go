package ignore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/ignore"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestLoadAndMatch(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".depfuseignore"), []byte(`
findings:
  - id: CVE-2024-0001
    reason: accepted risk
  - id: GHSA-xxxx-yyyy-zzzz
    package: next@15.1.0
    reason: scheduled upgrade
`), 0o644))

	rules, err := ignore.Load(root)
	require.NoError(t, err)

	f1 := models.Finding{
		Component: models.Component{Name: "lodash", Version: "4.17.21"},
		CveMatch:  models.CveMatch{CVEID: "CVE-2024-0001"},
	}
	reason, ok := rules.Match(f1)
	require.True(t, ok)
	require.Equal(t, "accepted risk", reason)

	f2 := models.Finding{
		Component: models.Component{Name: "next", Version: "15.1.0"},
		CveMatch:  models.CveMatch{GHSAID: "GHSA-xxxx-yyyy-zzzz", CVEID: "CVE-2024-0002"},
	}
	_, ok = rules.Match(f2)
	require.True(t, ok)

	f3 := models.Finding{
		Component: models.Component{Name: "next", Version: "14.0.0"},
		CveMatch:  models.CveMatch{GHSAID: "GHSA-xxxx-yyyy-zzzz"},
	}
	_, ok = rules.Match(f3)
	require.False(t, ok)
}

func TestApplyPartition(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".depfuseignore"), []byte(`
findings:
  - id: CVE-2024-0001
`), 0o644))
	rules, err := ignore.Load(root)
	require.NoError(t, err)

	in := []models.Finding{
		{CveMatch: models.CveMatch{CVEID: "CVE-2024-0001"}},
		{CveMatch: models.CveMatch{CVEID: "CVE-2024-0002"}},
	}
	out := ignore.Apply(in, rules)
	active, suppressed := ignore.Partition(out)
	require.Len(t, active, 1)
	require.Len(t, suppressed, 1)
	require.True(t, suppressed[0].Suppressed)
}
