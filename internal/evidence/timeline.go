package evidence

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/classify"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// BuildTimeline assembles the dated evidence timeline for a CVE.
func BuildTimeline(store *intel.Store, cveID string, impact *models.DecisionImpact) (*models.EvidenceTimeline, error) {
	if store == nil {
		return nil, fmt.Errorf("evidence timeline: nil store")
	}
	cveID = strings.TrimSpace(cveID)
	if cveID == "" {
		return nil, fmt.Errorf("evidence timeline: CVE id required")
	}

	cm := models.CveMatch{CVEID: cveID}
	classifier := &classify.Classifier{Store: store}
	class, err := classifier.Classify(cm)
	if err != nil {
		return nil, err
	}

	ids := append([]string{cm.CVEID, cm.OSVID, cm.GHSAID}, cm.Aliases...)
	artifacts, err := store.ArtifactsForAnyID(ids...)
	if err != nil {
		return nil, err
	}

	events := EventsFromArtifacts(artifacts)
	changedAt := class.Freshness
	if len(events) > 0 {
		changedAt = events[len(events)-1].At
	}

	state := models.EvidenceState{
		CVE:       cveID,
		Level:     class.Priority,
		Signals:   class.Signals,
		Hash:      Hash(class, artifacts),
		ChangedAt: changedAt,
		Events:    events,
	}

	return &models.EvidenceTimeline{
		CVE:            cveID,
		State:          state,
		DecisionImpact: impact,
	}, nil
}

// EventsFromArtifacts converts intel artifacts into sorted timeline events.
func EventsFromArtifacts(artifacts []models.RawArtifact) []models.EvidenceEvent {
	out := make([]models.EvidenceEvent, 0, len(artifacts))
	for _, a := range artifacts {
		if a.Source == models.SourceEPSS {
			score := a.Metadata["score"]
			if score == "" && a.Metadata != nil {
				score = a.Metadata["score"]
			}
			summary := "EPSS score indexed"
			if score != "" {
				summary = fmt.Sprintf("EPSS score %s", score)
			}
			out = append(out, models.EvidenceEvent{
				At: a.ObservedAt, Source: a.Source, Title: a.Title, URL: a.URL, Summary: summary,
			})
			continue
		}
		out = append(out, models.EvidenceEvent{
			At: a.ObservedAt, Source: a.Source, Title: a.Title, URL: a.URL,
			Summary: eventSummary(a),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].At.Equal(out[j].At) {
			return out[i].Source < out[j].Source
		}
		return out[i].At.Before(out[j].At)
	})
	return out
}

func eventSummary(a models.RawArtifact) string {
	switch a.Source {
	case models.SourceKEV:
		if strings.HasPrefix(a.ID, "KEV-CITE:") {
			return "Active exploitation cited"
		}
		return "Listed in KEV catalog"
	case models.SourceNuclei:
		return "Nuclei template indexed"
	case models.SourceMetasploit:
		return "Metasploit module indexed"
	case models.SourceExploitDB:
		return "Exploit-DB entry indexed"
	case models.SourcePoCGitHub:
		return "Public PoC repository indexed"
	case models.SourceVulnCheckXDB:
		return "VulnCheck XDB PoC indexed"
	default:
		return a.Title
	}
}

// ClassifyCVE returns classification + artifacts for a CVE id.
func ClassifyCVE(store *intel.Store, cveID string) (models.Classification, []models.RawArtifact, error) {
	cm := models.CveMatch{CVEID: cveID}
	cl := &classify.Classifier{Store: store}
	class, err := cl.Classify(cm)
	if err != nil {
		return models.Classification{}, nil, err
	}
	ids := append([]string{cm.CVEID, cm.OSVID, cm.GHSAID}, cm.Aliases...)
	arts, err := store.ArtifactsForAnyID(ids...)
	if err != nil {
		return models.Classification{}, nil, err
	}
	return class, arts, nil
}

// LatestEventAt returns the newest observed_at among artifacts, or zero.
func LatestEventAt(artifacts []models.RawArtifact) time.Time {
	var latest time.Time
	for _, a := range artifacts {
		if a.ObservedAt.After(latest) {
			latest = a.ObservedAt
		}
	}
	return latest
}
