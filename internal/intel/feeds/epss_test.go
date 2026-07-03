package feeds

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseEPSSCSV(t *testing.T) {
	raw := `#model_version:v2026.06.15,score_date:2026-06-15T12:03:41Z
cve,epss,percentile
CVE-2026-33032,0.38477,0.98383
CVE-2026-0257,0.18583,0.96882
CVE-2026-35273,0.00717,0.48772
not-a-cve,0.5,0.5
`
	recs, err := parseEPSSCSV(bytes.NewReader([]byte(raw)), "run-1")
	require.NoError(t, err)
	require.Len(t, recs, 3)

	byCVE := map[string]float64{}
	for _, r := range recs {
		require.NotNil(t, r.Artifact.EPSSScore)
		byCVE[r.CanonicalID] = *r.Artifact.EPSSScore
	}
	require.InDelta(t, 0.38477, byCVE["CVE-2026-33032"], 0.00001)
	require.InDelta(t, 0.18583, byCVE["CVE-2026-0257"], 0.00001)
	require.InDelta(t, 0.00717, byCVE["CVE-2026-35273"], 0.00001)
}
