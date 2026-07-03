package brief_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/brief"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestTemplateBriefingHasEvidence(t *testing.T) {
	class := models.Classification{
		Priority: models.PriorityP1,
		Evidence: []models.Citation{{
			Claim: "Nuclei template exists", Source: models.SourceNuclei, URL: "https://example.com",
		}},
		Signals: models.Signals{Nuclei: true},
	}
	text := brief.Render(
		models.Component{Name: "express", Version: "4.17.1"},
		models.CveMatch{CVEID: "CVE-2022-22965", Summary: "Spring RCE"},
		class, models.VerdictFixNow, "hold",
	)
	require.Contains(t, text, "CVE-2022-22965")
	require.Contains(t, text, "Nuclei")
	require.True(t, brief.ValidateGrounding(class, text))
}

func TestAbstainOnSilence(t *testing.T) {
	class := models.Classification{Priority: models.PriorityP2, Evidence: nil}
	text := brief.Render(
		models.Component{Name: "pkg", Version: "1.0.0"},
		models.CveMatch{CVEID: "CVE-2020-0001"},
		class, models.VerdictFixSoon, "fix",
	)
	require.Contains(t, text, "abstaining")
}

func TestExploitDBNarrative(t *testing.T) {
	class := models.Classification{
		Priority: models.PriorityP2,
		Evidence: []models.Citation{{
			Claim: "Exploit-DB entry indexed", Source: models.SourceExploitDB, URL: "https://example.com",
		}},
		Signals: models.Signals{ExploitDB: true},
	}
	text := brief.Render(
		models.Component{Name: "jquery", Version: "3.2.1"},
		models.CveMatch{CVEID: "CVE-2019-11358"},
		class, models.VerdictFixSoon, "fix",
	)
	require.Contains(t, text, "Exploit-DB")
	require.NotContains(t, text, "No weaponization evidence available from indexed sources")
	require.True(t, brief.ValidateGrounding(class, text))
}
