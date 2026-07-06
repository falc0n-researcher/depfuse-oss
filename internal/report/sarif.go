package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool         `json:"tool"`
	Results    []sarifResult     `json:"results"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// RenderSARIF writes SARIF 2.1.0 for GitHub Code Scanning and compatible tools.
func RenderSARIF(w io.Writer, result models.ScanResult, toolVersion string) error {
	if toolVersion == "" {
		toolVersion = "0.0.0"
	}

	rules := map[string]sarifRule{}
	var results []sarifResult

	for _, f := range result.Findings {
		ruleID := canonicalRuleID(f)
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = sarifRule{
				ID:   ruleID,
				Name: ruleID,
				ShortDescription: struct {
					Text string `json:"text"`
				}{Text: f.CveMatch.Summary},
				FullDescription: struct {
					Text string `json:"text"`
				}{Text: firstNonEmpty(f.CveMatch.Summary, f.VerdictReason)},
				DefaultConfiguration: struct {
					Level string `json:"level"`
				}{Level: sarifLevel(f.Classification.Priority)},
				Properties: map[string]string{
					"security-severity": tierSeverity(f.Classification.Priority),
					"tags":              "security,dependency,npm",
				},
			}
		}

		uri := "package.json"
		if f.Component.Manifest != "" {
			uri = f.Component.Manifest
		}
		msg := fmt.Sprintf("%s in %s@%s — %s (%s)",
			ruleID, f.Component.Name, f.Component.Version, f.Verdict, f.Classification.Priority)
		if f.VerdictReason != "" {
			msg += ": " + f.VerdictReason
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Classification.Priority),
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: uri},
				},
			}},
			Properties: map[string]string{
				"level":          f.Classification.Priority.String(),
				"verdict":        string(f.Verdict),
				"package":        f.Component.Name,
				"version":        f.Component.Version,
				"scope":          string(f.Component.Scope),
				"exposureNote":   f.ExposureNote,
				"dependencyPath": strings.Join(f.Component.Path, " → "),
			},
		})
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    "Depfuse",
					Version: toolVersion,
					Rules:   ruleList,
				},
			},
			Results:    results,
			Properties: coverageProperties(result.Meta.Coverage),
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// coverageProperties surfaces scan coverage on the SARIF run so a viewer
// doesn't mistake a clean results list for complete coverage.
func coverageProperties(cov *models.ScanCoverageMeta) map[string]string {
	if cov == nil {
		return nil
	}
	props := map[string]string{
		"coverageStatus":      cov.Status,
		"coverageMessage":     cov.Message,
		"unresolvedCount":     fmt.Sprintf("%d", cov.UnresolvedCount),
		"peerDependencyCount": fmt.Sprintf("%d", cov.PeerDependencyCount),
	}
	if cov.SnapshotMode != "" {
		props["snapshotMode"] = cov.SnapshotMode
	}
	return props
}

func canonicalRuleID(f models.Finding) string {
	if id := strings.TrimSpace(f.CveMatch.CVEID); strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range f.CveMatch.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	if f.CveMatch.GHSAID != "" {
		return f.CveMatch.GHSAID
	}
	if strings.HasPrefix(f.CveMatch.CVEID, "GHSA-") {
		return f.CveMatch.CVEID
	}
	if f.CveMatch.OSVID != "" {
		return f.CveMatch.OSVID
	}
	return f.CveMatch.CVEID
}

func sarifLevel(tier models.Priority) string {
	switch tier {
	case models.PriorityP0, models.PriorityP1:
		return "error"
	case models.PriorityP2:
		return "warning"
	default:
		return "note"
	}
}

func tierSeverity(tier models.Priority) string {
	switch tier {
	case models.PriorityP0:
		return "9.5"
	case models.PriorityP1:
		return "8.0"
	case models.PriorityP2:
		return "6.0"
	case models.PriorityP3:
		return "4.0"
	default:
		return "0.1"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
