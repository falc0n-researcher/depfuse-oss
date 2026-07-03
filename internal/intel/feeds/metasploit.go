package feeds

import (
	"context"
	"encoding/json"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const msfURL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

// Metasploit ingests MSF module metadata.
type Metasploit struct{}

func (f *Metasploit) Name() string { return "METASPLOIT" }

func (f *Metasploit) Fetch(ctx context.Context, runID string) ([]intel.NormalizedRecord, error) {
	_, body, err := FetchHTTPStatus(ctx, msfURL)
	if err != nil {
		return nil, err
	}
	var modules map[string]json.RawMessage
	if err := json.Unmarshal(body, &modules); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	byCVE := map[string]string{}
	for name, raw := range modules {
		var meta struct {
			References []string `json:"references"`
		}
		_ = json.Unmarshal(raw, &meta)
		for _, ref := range meta.References {
			for _, cve := range cveInText.FindAllString(ref, -1) {
				byCVE[cve] = name
			}
		}
	}
	var out []intel.NormalizedRecord
	for cve, mod := range byCVE {
		out = append(out, intel.NormalizedRecord{
			CanonicalID: cve,
			Aliases:     []intel.AliasInput{{Alias: cve, AliasType: "CVE"}},
			Artifact: intel.ArtifactInput{
				ID: "MSF:" + cve + ":" + mod, Source: models.SourceMetasploit, TrustClass: models.TrustHigh,
				Title: "Metasploit module: " + mod, URL: "https://github.com/rapid7/metasploit-framework",
				ObservedAt: now, FeedRunID: runID, MSFModule: mod,
			},
		})
	}
	return out, nil
}
