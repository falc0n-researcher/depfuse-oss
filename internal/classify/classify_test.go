package classify_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/classify"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func tempStore(t *testing.T) *intel.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intel.db")
	s, err := intel.Open(path)
	require.NoError(t, err)
	require.NoError(t, intel.SeedDemoData(s))
	t.Cleanup(func() { s.Close() })
	return s
}

func TestVulnCheckKEVAndXDBCitations(t *testing.T) {
	s := tempStore(t)
	now := time.Now().UTC()
	arts := []models.RawArtifact{
		{ID: "KEV:CVE-2024-4577", CVEID: "CVE-2024-4577", Source: models.SourceKEV,
			TrustClass: models.TrustAuthoritative, Title: "VC KEV entry",
			URL: "https://vulncheck.com/kev", ObservedAt: now},
		{ID: "KEV-CITE:CVE-2024-4577:abc", CVEID: "CVE-2024-4577", Source: models.SourceKEV,
			TrustClass: models.TrustAuthoritative, Title: "Exploitation evidence",
			URL: "https://isc.sans.edu/diary/example", ObservedAt: now},
		{ID: "XDB:024996c990cc", CVEID: "CVE-2024-4577", Source: models.SourceVulnCheckXDB,
			TrustClass: models.TrustHigh, MaturityTag: models.MaturityVerified,
			Title: "VulnCheck XDB PoC", URL: "https://vulncheck.com/xdb/024996c990cc", ObservedAt: now},
	}
	for _, a := range arts {
		require.NoError(t, s.UpsertArtifact(a))
	}
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{CVEID: "CVE-2024-4577"})
	require.NoError(t, err)
	require.Equal(t, models.PriorityP0, class.Priority)
	require.True(t, class.Signals.KEV)
	require.GreaterOrEqual(t, len(class.Evidence), 3)
	var hasPrimary bool
	for _, e := range class.Evidence {
		if strings.Contains(e.Claim, "VulnCheck KEV") {
			hasPrimary = true
		}
	}
	require.True(t, hasPrimary)
}

func TestXDBIsCitationOnlyAndNonTiering(t *testing.T) {
	s := tempStore(t)
	now := time.Now().UTC()
	require.NoError(t, s.UpsertArtifact(models.RawArtifact{
		ID: "XDB:024996c990cc", CVEID: "CVE-2099-0001", Source: models.SourceVulnCheckXDB,
		TrustClass: models.TrustHigh, MaturityTag: models.MaturityVerified,
		Title: "VulnCheck XDB PoC", URL: "https://vulncheck.com/xdb/024996c990cc", ObservedAt: now,
	}))
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{CVEID: "CVE-2099-0001"})
	require.NoError(t, err)

	// XDB alone must never elevate priority — it's enrichment, not a tiering signal.
	require.Equal(t, models.PriorityP4, class.Priority)
	require.False(t, class.Signals.KEV)
	require.False(t, class.Signals.Nuclei)
	require.False(t, class.Signals.Metasploit)

	require.Len(t, class.Evidence, 1)
	require.Contains(t, class.Evidence[0].Claim, "citation only, does not affect priority tier")
}

func TestGHSAAliasResolvesArtifacts(t *testing.T) {
	s := tempStore(t)
	require.NoError(t, s.UpsertAlias("GHSA-jfhv-c572-7mpm", "CVE-2021-44228"))

	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{
		CVEID: "GHSA-jfhv-c572-7mpm", GHSAID: "GHSA-jfhv-c572-7mpm",
		Summary: "Log4Shell via GHSA",
	})
	require.NoError(t, err)
	require.Equal(t, models.PriorityP0, class.Priority)
	require.True(t, class.Signals.KEV)
}

func TestKEVIsT0(t *testing.T) {
	s := tempStore(t)
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{CVEID: "CVE-2021-44228", Summary: "Log4Shell"})
	require.NoError(t, err)
	require.Equal(t, models.PriorityP0, class.Priority)
	require.True(t, class.Signals.KEV)
}

func TestNucleiMSFIsT1(t *testing.T) {
	s := tempStore(t)
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{CVEID: "CVE-2022-22965", Summary: "Spring4Shell"})
	require.NoError(t, err)
	require.Equal(t, models.PriorityP0, class.Priority) // KEV also present
	require.True(t, class.Signals.Metasploit)
}

func TestUnverifiedPoCMaxT2(t *testing.T) {
	s := tempStore(t)
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{CVEID: "CVE-2020-8209", Summary: "Citrix"})
	require.NoError(t, err)
	require.LessOrEqual(t, int(class.Priority), int(models.PriorityP2))
	require.True(t, class.Signals.PoCPresent)
}

func TestLowEPSSNoExploitIsT4(t *testing.T) {
	s := tempStore(t)
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{
		CVEID: "CVE-2023-26136", Summary: "Low risk", Severity: "CVSS_V3:9.0",
	})
	require.NoError(t, err)
	require.Equal(t, models.PriorityP4, class.Priority)
}

func TestOSVOnlyNoSignalIsQuiet(t *testing.T) {
	// No exploit signal and no EPSS score → Quiet (T4), not Watch. Silence
	// defaults down so advisories lacking EPSS coverage do not inflate Watch.
	s := tempStore(t)
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{
		OSVID:   "GHSA-xxxx-yyyy-zzzz",
		GHSAID:  "GHSA-xxxx-yyyy-zzzz",
		Summary: "Advisory without CVE alias or severity",
	})
	require.NoError(t, err)
	require.Equal(t, models.PriorityP4, class.Priority)
}

func TestElevatedEPSSNoExploitIsWatch(t *testing.T) {
	// A non-negligible EPSS score with no exploit signal is the positive watch
	// signal that earns Watch (T3).
	s := tempStore(t)
	require.NoError(t, s.UpsertArtifact(models.RawArtifact{
		ID: "epss-watch", CVEID: "CVE-2024-00001", Source: models.SourceEPSS,
		TrustClass: models.TrustHigh, Title: "EPSS score", ObservedAt: time.Now().UTC(),
		Metadata: map[string]string{"score": "0.30"},
	}))
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{CVEID: "CVE-2024-00001", Summary: "Elevated EPSS, no exploit"})
	require.NoError(t, err)
	require.Equal(t, models.PriorityP3, class.Priority)
}

func TestLowEPSSWithoutSeverityIsT4(t *testing.T) {
	s := tempStore(t)
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{
		CVEID: "CVE-2023-26136", Summary: "Low EPSS demotion",
	})
	require.NoError(t, err)
	require.Equal(t, models.PriorityP4, class.Priority)
}

func TestNucleiEvidenceUsesTemplateFileURL(t *testing.T) {
	s := tempStore(t)
	require.NoError(t, s.UpsertArtifact(models.RawArtifact{
		ID: "nuclei-generic-url", CVEID: "CVE-2025-29927", Source: models.SourceNuclei,
		TrustClass: models.TrustHigh, Title: "Nuclei template: CVE-2025-29927",
		URL: "https://github.com/projectdiscovery/nuclei-templates", ObservedAt: time.Now().UTC(),
		Metadata: map[string]string{"templateId": "CVE-2025-29927"},
	}))
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{CVEID: "CVE-2025-29927"})
	require.NoError(t, err)
	var nucleiURL string
	for _, e := range class.Evidence {
		if e.Source == models.SourceNuclei {
			nucleiURL = e.URL
		}
	}
	require.Contains(t, nucleiURL, "http/cves/2025/CVE-2025-29927.yaml")
}

func TestMaxTierForPoC(t *testing.T) {
	require.Equal(t, models.PriorityP2, classify.MaxTierForPoC(false))
	require.Equal(t, models.PriorityP1, classify.MaxTierForPoC(true))
}

func TestFreshnessStamped(t *testing.T) {
	s := tempStore(t)
	cl := &classify.Classifier{Store: s}
	class, err := cl.Classify(models.CveMatch{CVEID: "CVE-2021-44228"})
	require.NoError(t, err)
	require.False(t, class.Freshness.IsZero())
	require.WithinDuration(t, time.Now().UTC(), class.Freshness, 24*time.Hour)
}
