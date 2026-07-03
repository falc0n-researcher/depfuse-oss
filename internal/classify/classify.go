package classify

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel/feeds"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// Classifier assigns exploit-risk levels from intelligence artifacts.
type Classifier struct {
	Store *intel.Store
}

// Classify assigns tier, confidence, and evidence for a CVE.
func (c *Classifier) Classify(cve models.CveMatch) (models.Classification, error) {
	var artifacts []models.RawArtifact
	var err error
	if c.Store != nil {
		ids := append([]string{cve.CVEID, cve.OSVID, cve.GHSAID}, cve.Aliases...)
		artifacts, err = c.Store.ArtifactsForAnyID(ids...)
		if err != nil {
			return models.Classification{}, err
		}
	}

	signals := models.Signals{}
	var evidence []models.Citation
	var freshest time.Time
	trustSum := 0.0
	sourceCount := 0

	for _, a := range artifacts {
		if a.ObservedAt.After(freshest) {
			freshest = a.ObservedAt
		}
		trustSum += trustWeight(a.TrustClass)
		sourceCount++

		switch a.Source {
		case models.SourceKEV:
			signals.KEV = true
			claim := "Listed in VulnCheck Known Exploited Vulnerabilities catalog"
			if strings.HasPrefix(a.ID, "KEV-CITE:") {
				claim = "Active exploitation cited by VulnCheck KEV"
			}
			evidence = append(evidence, cite(a, claim))
		case models.SourceVulnCheckXDB:
			evidence = append(evidence, cite(a, "VulnCheck XDB indexes validated proof-of-concept exploit code (metadata only)"))
		case models.SourceNuclei:
			signals.Nuclei = true
			evidence = append(evidence, cite(a, "Nuclei scanner template exists for this CVE"))
		case models.SourceMetasploit:
			signals.Metasploit = true
			evidence = append(evidence, cite(a, "Metasploit framework module references this CVE"))
		case models.SourceExploitDB:
			signals.ExploitDB = true
			evidence = append(evidence, cite(a, "Exploit-DB entry indexed for this CVE"))
		case models.SourcePoCGitHub:
			signals.PoCPresent = true
			if a.MaturityTag == models.MaturityVerified {
				signals.PoCVerified = true
			}
			evidence = append(evidence, cite(a, "Public PoC repository referenced (metadata only)"))
		case models.SourceEPSS:
			if a.Metadata != nil {
				if scoreStr, ok := a.Metadata["score"]; ok {
					if score, err := strconv.ParseFloat(scoreStr, 64); err == nil {
						signals.EPSS = score
					}
				}
			}
		}
	}

	tier := computePriority(signals)
	// Enforce unverified PoC cap at T2
	if tier > models.PriorityP2 && signals.PoCPresent && !signals.PoCVerified && !signals.KEV && !signals.Nuclei && !signals.Metasploit {
		tier = models.PriorityP2
	}

	confidence := 0.5
	if sourceCount > 0 {
		confidence = math.Min(1.0, (trustSum/float64(sourceCount))*corroborationFactor(sourceCount))
	}

	if freshest.IsZero() {
		freshest = cve.Published
	}
	if freshest.IsZero() {
		freshest = time.Now().UTC()
	}

	if len(evidence) == 0 && cve.Summary != "" {
		evidence = append(evidence, models.Citation{
			Claim:  cve.Summary,
			Source: models.SourceOSV,
			URL:    firstRef(cve.References),
			Title:  cve.OSVID,
		})
	}

	return models.Classification{
		Priority:   tier,
		Confidence: confidence,
		Band:       models.BandFor(confidence),
		Freshness:  freshest,
		Evidence:   evidence,
		Signals:    signals,
	}, nil
}

func computePriority(s models.Signals) models.Priority {
	if s.KEV {
		return models.PriorityP0
	}
	if s.Nuclei || s.Metasploit || s.PoCVerified {
		return models.PriorityP1
	}
	if s.PoCPresent || s.ExploitDB {
		return models.PriorityP2
	}
	// No indexed exploit signal. Reserve Watch (T3) for a *positive* watch
	// signal — a non-negligible EPSS exploitation-likelihood score. With no
	// score, or a low one, the finding is Quiet (T4): a confirmed dependency
	// match with nothing indicating real-world exploitation. Defaulting silence
	// to T4 (not T3) keeps the actionable + watch buckets small and honest —
	// otherwise every advisory lacking EPSS coverage inflates Watch.
	if s.EPSS >= 0.05 {
		return models.PriorityP3
	}
	return models.PriorityP4
}

func trustWeight(t models.TrustClass) float64 {
	switch t {
	case models.TrustAuthoritative:
		return 1.0
	case models.TrustHigh:
		return 0.85
	case models.TrustMedium:
		return 0.6
	default:
		return 0.35
	}
}

func corroborationFactor(n int) float64 {
	if n >= 3 {
		return 1.0
	}
	if n == 2 {
		return 0.9
	}
	return 0.75
}

func cite(a models.RawArtifact, claim string) models.Citation {
	return models.Citation{Claim: claim, Source: a.Source, URL: resolveArtifactURL(a), Title: a.Title}
}

func resolveArtifactURL(a models.RawArtifact) string {
	if a.Source != models.SourceNuclei {
		return a.URL
	}
	if p := a.Metadata["templatePath"]; p != "" {
		return feeds.NucleiBlobURL(p)
	}
	if feeds.IsGenericNucleiRepoURL(a.URL) {
		if p := feeds.InferNucleiTemplatePath(a.CVEID); p != "" {
			return feeds.NucleiBlobURL(p)
		}
	}
	return a.URL
}

func firstRef(refs []string) string {
	if len(refs) > 0 {
		return refs[0]
	}
	return ""
}

// MaxTierForPoC returns the tier cap for unverified PoCs (T2).
func MaxTierForPoC(verified bool) models.Priority {
	if verified {
		return models.PriorityP1
	}
	return models.PriorityP2
}
