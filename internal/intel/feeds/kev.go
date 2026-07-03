package feeds

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const (
	VulnCheckKEVURL       = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
	kevJSONName           = "vulncheck_known_exploited_vulnerabilities.json"
	maxKEVCitationsPerCVE = 3
)

// KEV ingests VulnCheck Known Exploited Vulnerabilities (Community).
type KEV struct {
	BaseURL string // test override
}

func (f *KEV) Name() string { return "KEV" }

type vcBackupResponse struct {
	Data []vcBackupLink `json:"data"`
}

type vcBackupLink struct {
	Filename string `json:"filename"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
}

type vcKEVEntry struct {
	Name                          string              `json:"vulnerabilityName"`
	CVE                           []string            `json:"cve"`
	DateAdded                     time.Time           `json:"date_added"`
	CisaDateAdded                 *time.Time          `json:"cisa_date_added,omitempty"`
	VulnCheckXDB                  []vcXDB             `json:"vulncheck_xdb"`
	VulnCheckReportedExploitation []vcReportedExploit `json:"vulncheck_reported_exploitation"`
}

type vcReportedExploit struct {
	URL       string    `json:"url"`
	DateAdded time.Time `json:"date_added"`
}

type vcXDB struct {
	XDBID       string    `json:"xdb_id"`
	XDBURL      string    `json:"xdb_url"`
	DateAdded   time.Time `json:"date_added"`
	ExploitType string    `json:"exploit_type"`
	CloneSSHURL string    `json:"clone_ssh_url"`
}

func (f *KEV) Fetch(ctx context.Context, runID string) ([]intel.NormalizedRecord, error) {
	token := strings.TrimSpace(os.Getenv("DEPFUSE_VULNCHECK_TOKEN"))
	if token == "" {
		return nil, fmt.Errorf("KEV: DEPFUSE_VULNCHECK_TOKEN is required (free at https://vulncheck.com/kev)")
	}

	entries, err := f.fetchEntries(ctx, token)
	if err != nil {
		return nil, err
	}
	out := recordsFromKEVEntries(entries, runID)
	if len(out) == 0 {
		return nil, fmt.Errorf("KEV: parsed 0 artifacts from VulnCheck backup")
	}
	return out, nil
}

func (f *KEV) fetchEntries(ctx context.Context, token string) ([]vcKEVEntry, error) {
	base := VulnCheckKEVURL
	if f.BaseURL != "" {
		base = f.BaseURL
	}

	link, err := f.fetchBackupLink(ctx, base, token)
	if err != nil {
		return nil, err
	}
	zipBytes, err := downloadBytes(ctx, link.URL, 64<<20)
	if err != nil {
		return nil, fmt.Errorf("KEV: download backup: %w", err)
	}
	return parseKEVZip(zipBytes)
}

func (f *KEV) fetchBackupLink(ctx context.Context, url, token string) (vcBackupLink, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return vcBackupLink{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return vcBackupLink{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return vcBackupLink{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return vcBackupLink{}, fmt.Errorf("KEV: backup HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var meta vcBackupResponse
	if err := json.Unmarshal(body, &meta); err != nil {
		return vcBackupLink{}, err
	}
	if len(meta.Data) == 0 || meta.Data[0].URL == "" {
		return vcBackupLink{}, fmt.Errorf("KEV: backup response missing download URL")
	}
	return meta.Data[0], nil
}

func downloadBytes(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func parseKEVZip(zipBytes []byte) ([]vcKEVEntry, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("KEV: open zip: %w", err)
	}
	var jsonData []byte
	for _, f := range zr.File {
		if f.Name != kevJSONName && !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		jsonData, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		break
	}
	if len(jsonData) == 0 {
		return nil, fmt.Errorf("KEV: no JSON file in backup zip")
	}
	return unmarshalKEVEntries(jsonData)
}

func unmarshalKEVEntries(jsonData []byte) ([]vcKEVEntry, error) {
	var entries []vcKEVEntry
	if err := json.Unmarshal(jsonData, &entries); err == nil {
		return entries, nil
	}
	var wrapped struct {
		Data []vcKEVEntry `json:"data"`
	}
	if err := json.Unmarshal(jsonData, &wrapped); err != nil {
		return nil, fmt.Errorf("KEV: parse JSON: %w", err)
	}
	return wrapped.Data, nil
}

func recordsFromKEVEntries(entries []vcKEVEntry, runID string) []intel.NormalizedRecord {
	var out []intel.NormalizedRecord
	for _, entry := range entries {
		for _, cve := range entry.CVE {
			if cve == "" {
				continue
			}
			observed := entry.DateAdded
			if observed.IsZero() {
				observed = time.Now().UTC()
			}
			meta := map[string]string{}
			if entry.CisaDateAdded != nil && !entry.CisaDateAdded.IsZero() {
				meta["cisa_date_added"] = entry.CisaDateAdded.Format(time.RFC3339)
			}
			if n := len(entry.VulnCheckReportedExploitation); n > 0 {
				meta["citation_count"] = fmt.Sprint(n)
			}
			out = append(out, intel.NormalizedRecord{
				CanonicalID: cve,
				Aliases:     []intel.AliasInput{{Alias: cve, AliasType: "CVE"}},
				Artifact: intel.ArtifactInput{
					ID: "KEV:" + cve, Source: models.SourceKEV, TrustClass: models.TrustAuthoritative,
					Title: entry.Name, URL: "https://vulncheck.com/kev", ObservedAt: observed,
					FeedRunID: runID, Extra: meta,
				},
			})
			for i, cite := range topKEVCitations(entry.VulnCheckReportedExploitation, maxKEVCitationsPerCVE) {
				if cite.URL == "" {
					continue
				}
				citeAt := cite.DateAdded
				if citeAt.IsZero() {
					citeAt = observed
				}
				out = append(out, intel.NormalizedRecord{
					CanonicalID: cve,
					Aliases:     []intel.AliasInput{{Alias: cve, AliasType: "CVE"}},
					Artifact: intel.ArtifactInput{
						ID:     fmt.Sprintf("KEV-CITE:%s:%s", cve, shortHash(cite.URL)),
						Source: models.SourceKEV, TrustClass: models.TrustAuthoritative,
						Title: "Exploitation evidence", URL: cite.URL, ObservedAt: citeAt,
						FeedRunID: runID, Extra: map[string]string{"cite_index": fmt.Sprint(i)},
					},
				})
			}
			for _, x := range entry.VulnCheckXDB {
				if x.XDBID == "" {
					continue
				}
				xAt := x.DateAdded
				if xAt.IsZero() {
					xAt = observed
				}
				out = append(out, intel.NormalizedRecord{
					CanonicalID: cve,
					Aliases:     []intel.AliasInput{{Alias: cve, AliasType: "CVE"}},
					Artifact: intel.ArtifactInput{
						ID: "XDB:" + x.XDBID, Source: models.SourceVulnCheckXDB,
						TrustClass: models.TrustHigh, MaturityTag: models.MaturityVerified,
						Title: "VulnCheck XDB PoC: " + x.XDBID, URL: x.XDBURL,
						ObservedAt: xAt, FeedRunID: runID,
						Extra: map[string]string{
							"exploit_type":  x.ExploitType,
							"clone_ssh_url": x.CloneSSHURL,
						},
					},
				})
			}
		}
	}
	return out
}

func topKEVCitations(cites []vcReportedExploit, limit int) []vcReportedExploit {
	if limit <= 0 || len(cites) == 0 {
		return nil
	}
	sorted := append([]vcReportedExploit(nil), cites...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].DateAdded.After(sorted[j].DateAdded)
	})
	if len(sorted) > limit {
		sorted = sorted[:limit]
	}
	return sorted
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}
