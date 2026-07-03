package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

type hashPayload struct {
	Level       models.Priority `json:"level"`
	KEV         bool            `json:"kev"`
	Nuclei      bool            `json:"nuclei"`
	Metasploit  bool            `json:"metasploit"`
	ExploitDB   bool            `json:"exploitdb"`
	PoCPresent  bool            `json:"pocPresent"`
	PoCVerified bool            `json:"pocVerified"`
	EPSS        float64         `json:"epss"`
	ArtifactIDs []string        `json:"artifactIds"`
}

// Hash computes a deterministic evidence fingerprint from classification and artifacts.
func Hash(class models.Classification, artifacts []models.RawArtifact) string {
	ids := make([]string, 0, len(artifacts))
	seen := map[string]bool{}
	for _, a := range artifacts {
		if a.ID == "" || seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		ids = append(ids, a.ID)
	}
	sort.Strings(ids)

	payload := hashPayload{
		Level:       class.Priority,
		KEV:         class.Signals.KEV,
		Nuclei:      class.Signals.Nuclei,
		Metasploit:  class.Signals.Metasploit,
		ExploitDB:   class.Signals.ExploitDB,
		PoCPresent:  class.Signals.PoCPresent,
		PoCVerified: class.Signals.PoCVerified,
		EPSS:        roundEPSS(class.Signals.EPSS),
		ArtifactIDs: ids,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func roundEPSS(v float64) float64 {
	if v <= 0 {
		return 0
	}
	return float64(int(v*100+0.5)) / 100
}
