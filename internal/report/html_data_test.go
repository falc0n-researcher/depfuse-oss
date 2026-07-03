package report

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestOSVWebURL(t *testing.T) {
	require.Equal(t, "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm", osvWebURL("GHSA-35jh-r3h4-6jhm"))
	require.NotContains(t, osvWebURL("GHSA-35jh-r3h4-6jhm"), "/vulnerabilities/")
}

func TestCVEPrimaryURL(t *testing.T) {
	require.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2020-11022",
		cvePrimaryURL(models.CveMatch{CVEID: "CVE-2020-11022"}))
	require.Equal(t, "https://github.com/advisories/GHSA-gxr4-xjj5-5px2",
		cvePrimaryURL(models.CveMatch{CVEID: "GHSA-gxr4-xjj5-5px2", OSVID: "GHSA-gxr4-xjj5-5px2"}))
}

func TestCVEOSVURL(t *testing.T) {
	require.Equal(t, "https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2",
		cveOSVURL(models.CveMatch{OSVID: "GHSA-gxr4-xjj5-5px2", GHSAID: "GHSA-gxr4-xjj5-5px2"}))
}
