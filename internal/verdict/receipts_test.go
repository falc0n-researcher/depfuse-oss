package verdict

import (
	"strings"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func TestBuildReceiptsKEVAndExposure(t *testing.T) {
	comp := models.Component{Name: "next", Version: "15.1.0", LockfileRoot: "."}
	class := models.Classification{
		Priority: models.PriorityP0,
		Signals:  models.Signals{KEV: true, Nuclei: true},
		Evidence: []models.Citation{
			{Claim: "Listed in VulnCheck KEV", Source: models.SourceKEV, URL: "https://vulncheck.com/kev"},
			{Claim: "Nuclei template exists", Source: models.SourceNuclei, URL: "https://github.com/.../CVE.yaml"},
		},
	}
	recs := BuildReceipts(comp, models.CveMatch{CVEID: "CVE-2025-29927"}, class)
	if len(recs) < 3 {
		t.Fatalf("got %d receipts", len(recs))
	}
	if recs[0].Kind != models.ReceiptKEV {
		t.Fatalf("first kind %v", recs[0].Kind)
	}
	exposure := recs[len(recs)-1]
	if exposure.Kind != models.ReceiptExposure {
		t.Fatalf("exposure %v", exposure.Kind)
	}
	if !strings.Contains(exposure.Claim, "next@15.1.0") {
		t.Fatalf("claim %q", exposure.Claim)
	}
}
