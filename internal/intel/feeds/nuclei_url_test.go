package feeds_test

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel/feeds"
	"github.com/stretchr/testify/require"
)

func TestNucleiBlobURL(t *testing.T) {
	require.Equal(t,
		"https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-29927.yaml",
		feeds.NucleiBlobURL("http/cves/2025/CVE-2025-29927.yaml"),
	)
}

func TestInferNucleiTemplatePath(t *testing.T) {
	require.Equal(t, "http/cves/2025/CVE-2025-29927.yaml", feeds.InferNucleiTemplatePath("CVE-2025-29927"))
	require.Empty(t, feeds.InferNucleiTemplatePath("not-a-cve"))
}

func TestIsGenericNucleiRepoURL(t *testing.T) {
	require.True(t, feeds.IsGenericNucleiRepoURL("https://github.com/projectdiscovery/nuclei-templates"))
	require.True(t, feeds.IsGenericNucleiRepoURL("https://github.com/projectdiscovery/nuclei-templates/"))
	require.False(t, feeds.IsGenericNucleiRepoURL("https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-29927.yaml"))
}
