package models

import "time"

// Source identifies an intelligence feed.
type Source string

const (
	SourceKEV          Source = "KEV"
	SourceEPSS         Source = "EPSS"
	SourceNuclei       Source = "NUCLEI"
	SourceMetasploit   Source = "METASPLOIT"
	SourceExploitDB    Source = "EXPLOITDB"
	SourcePoCGitHub    Source = "POC_GITHUB"
	SourceVulnCheckXDB Source = "VULNCHECK_XDB"
	SourceOSV          Source = "OSV"
)

// TrustClass indicates source reliability for classification.
type TrustClass string

const (
	TrustAuthoritative TrustClass = "authoritative"
	TrustHigh          TrustClass = "high"
	TrustMedium        TrustClass = "medium"
	TrustLow           TrustClass = "low"
)

// MaturityTag describes PoC maturity.
type MaturityTag string

const (
	MaturityREADMEOnly MaturityTag = "README-only"
	MaturityHasCode    MaturityTag = "has-code"
	MaturityVerified   MaturityTag = "verified"
)

// RawArtifact is a normalized intelligence record keyed by CVE.
type RawArtifact struct {
	ID          string            `json:"id"`
	CVEID       string            `json:"cveId"`
	Source      Source            `json:"source"`
	TrustClass  TrustClass        `json:"trustClass"`
	MaturityTag MaturityTag       `json:"maturityTag,omitempty"`
	Title       string            `json:"title"`
	URL         string            `json:"url,omitempty"`
	ObservedAt  time.Time         `json:"observedAt"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
