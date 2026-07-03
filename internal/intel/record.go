package intel

import (
	"regexp"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

// AliasInput is one alias for a vulnerability.
type AliasInput struct {
	Alias     string
	AliasType string // CVE | GHSA | OSV | NPM
}

// NormalizedRecord is the collector output unit.
type NormalizedRecord struct {
	CanonicalID string
	Summary     string
	Aliases     []AliasInput
	Artifact    ArtifactInput
}

// ArtifactInput is typed artifact fields for upsert.
type ArtifactInput struct {
	ID             string
	Source         models.Source
	TrustClass     models.TrustClass
	MaturityTag    models.MaturityTag
	Title          string
	URL            string
	ObservedAt     time.Time
	FeedRunID      string
	EPSSScore      *float64
	NucleiTemplate string
	MSFModule      string
	EDBID          string
	PoCRepo        string
	PoCStars       *int
	Extra          map[string]string
}

// InferAliasType returns CVE, GHSA, OSV, or NPM.
func InferAliasType(id string) string {
	switch {
	case cvePattern.MatchString(id):
		return "CVE"
	case strings.HasPrefix(id, "GHSA-"):
		return "GHSA"
	case strings.HasPrefix(id, "NPM-"):
		return "NPM"
	default:
		return "OSV"
	}
}

// VulnID returns stable internal vulnerability id.
func VulnID(canonical string) string {
	return "vuln:" + canonical
}

// PickCanonical prefers CVE over GHSA over other aliases.
func PickCanonical(ids ...string) string {
	for _, id := range ids {
		if cvePattern.MatchString(id) {
			return id
		}
	}
	for _, id := range ids {
		if strings.HasPrefix(id, "GHSA-") {
			return id
		}
	}
	for _, id := range ids {
		if id != "" {
			return id
		}
	}
	return ""
}
