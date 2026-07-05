package scan

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestPackageNamesForContextIncludesTransitiveFindings(t *testing.T) {
	findings := []models.Finding{{
		Component: models.Component{Name: "qs", Version: "6.7.0", Direct: false},
		Verdict:   models.VerdictOK,
	}}
	names := packageNamesForContext(findings, nil)
	require.Equal(t, []string{"qs"}, names)
}

func TestPackageNamesForContextIncludesAllComponents(t *testing.T) {
	components := []models.Component{
		{Name: "express", Version: "4.17.1", Direct: true},
		{Name: "qs", Version: "6.7.0", Direct: false},
	}
	names := packageNamesForContext(nil, components)
	require.ElementsMatch(t, []string{"express", "qs"}, names)
}
