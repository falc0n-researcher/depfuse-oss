package feeds

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractNucleiCVEsStructured(t *testing.T) {
	yamlDoc := `
id: CVE-2025-29927-check
info:
  name: Next.js Middleware Authorization Bypass
  description: Checks CVE-2025-29927
  classification:
    cve-id:
      - CVE-2025-29927
  tags: cve,cve2025,nextjs
`
	id, cves := extractNucleiCVEs([]byte(yamlDoc))
	require.Equal(t, "CVE-2025-29927-check", id)
	require.Contains(t, cves, "CVE-2025-29927")
}

func TestExtractNucleiCVEsIgnoresFileComment(t *testing.T) {
	yamlDoc := `# CVE-2099-0001 appears only in a YAML comment
id: demo-template
info:
  name: Safe template
  tags: demo
`
	_, cves := extractNucleiCVEs([]byte(yamlDoc))
	require.Empty(t, cves)
}

func TestExtractNucleiCVEsFromTags(t *testing.T) {
	yamlDoc := `
id: tagged
info:
  name: tagged template
  tags: cve,cve2024,CVE-2024-23897
`
	_, cves := extractNucleiCVEs([]byte(yamlDoc))
	require.Contains(t, cves, "CVE-2024-23897")
}

func TestExtractNucleiCVEsClassificationString(t *testing.T) {
	id, cves := extractNucleiCVEs([]byte(`
id: log4shell
info:
  classification:
    cve-id: CVE-2021-44228
`))
	require.Equal(t, "log4shell", id)
	require.Equal(t, []string{"CVE-2021-44228"}, cves)
}
