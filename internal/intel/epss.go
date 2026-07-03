package intel

import (
	"strconv"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// IngestEPSS loads EPSS scores from a map.
func IngestEPSS(s *Store, scores map[string]float64) error {
	now := time.Now().UTC()
	for cve, score := range scores {
		_ = s.UpsertArtifact(models.RawArtifact{
			ID:         "epss-" + cve,
			CVEID:      cve,
			Source:     models.SourceEPSS,
			TrustClass: models.TrustMedium,
			Title:      "EPSS score",
			ObservedAt: now,
			Metadata:   map[string]string{"score": strconv.FormatFloat(score, 'f', 4, 64)},
		})
	}
	return nil
}
