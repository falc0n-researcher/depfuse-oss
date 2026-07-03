package match

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const defaultOSVBatchURL = "https://api.osv.dev/v1/querybatch"
const defaultOSVQueryURL = "https://api.osv.dev/v1/query"

var osvBatchURL = defaultOSVBatchURL
var osvQueryURL = defaultOSVQueryURL

// SetOSVBatchURLForTest overrides the OSV batch endpoint (tests only).
func SetOSVBatchURLForTest(url string) {
	osvBatchURL = url
}

// OSVBatchURLForTest returns the current OSV batch endpoint.
func OSVBatchURLForTest() string {
	return osvBatchURL
}

// SetOSVQueryURLForTest overrides the OSV query endpoint (tests only).
func SetOSVQueryURLForTest(url string) {
	osvQueryURL = url
}

// OSVQueryURLForTest returns the current OSV query endpoint.
func OSVQueryURLForTest() string {
	return osvQueryURL
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

// Stats records OSV matching telemetry for a single MatchComponents call.
type Stats struct {
	OSVCacheHits int `json:"osvCacheHits"`
	OSVQueries   int `json:"osvQueries"`
	OSVChunks    int `json:"osvChunks"`
}

// Client queries OSV for vulnerability matches.
type Client struct {
	HTTP      *http.Client
	Offline   bool
	OfflineDB OfflineReader
	cache     map[string][]models.CveMatch
	Stats     Stats
}

// OfflineReader loads cached OSV responses from snapshot.
type OfflineReader interface {
	GetOSVMatches(ecosystem, name, version string) ([]models.CveMatch, bool)
}

// OfflineMatcher resolves advisories from the local OSV npm advisory index by
// evaluating version ranges, so offline scans work after `collect` alone.
type OfflineMatcher interface {
	HasOSVNPM() bool
	MatchNPM(name, version string) ([]models.CveMatch, bool)
}

// ComponentMatch pairs a component with its CVE matches.
type ComponentMatch struct {
	Component models.Component
	Matches   []models.CveMatch
}

type batchRequest struct {
	Queries []query `json:"queries"`
}

type query struct {
	Package packageRef `json:"package"`
	Version string     `json:"version"`
}

type packageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type batchResponse struct {
	Results []result `json:"results"`
}

type result struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID         string        `json:"id"`
	Summary    string        `json:"summary"`
	Aliases    []string      `json:"aliases"`
	Published  string        `json:"published"`
	Severity   []osvSeverity `json:"severity"`
	Affected   []osvAffected `json:"affected"`
	References []osvRef      `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package packageRef `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type queryTarget struct {
	q       query
	indices []int
}

type osvAPIError struct {
	StatusCode int
	Body       string
}

func (e *osvAPIError) Error() string {
	return fmt.Sprintf("osv api error: http %d: %s", e.StatusCode, e.Body)
}

// MatchComponents queries OSV for all components.
func (c *Client) MatchComponents(ctx context.Context, components []models.Component) ([]ComponentMatch, error) {
	if c.cache == nil {
		c.cache = map[string][]models.CveMatch{}
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	c.Stats = Stats{}

	out := make([]ComponentMatch, len(components))
	var jobs []queryTarget
	jobIndex := map[string]int{}

	for i, comp := range components {
		// Components without a concrete version (manifest-only ranges that could
		// not be pinned) are not matchable — querying OSV with "" or "*" yields
		// nothing useful and risks false negatives presented as clean.
		if comp.Unresolved || comp.Version == "" || comp.Version == "*" {
			out[i] = ComponentMatch{Component: comp, Matches: nil}
			continue
		}
		key := cacheKey(comp)
		if cached, ok := c.cache[key]; ok {
			out[i] = ComponentMatch{Component: comp, Matches: cached}
			continue
		}
		if c.OfflineDB != nil {
			if matches, ok := c.OfflineDB.GetOSVMatches("npm", comp.Name, comp.Version); ok {
				c.cache[key] = matches
				c.Stats.OSVCacheHits++
				out[i] = ComponentMatch{Component: comp, Matches: matches}
				continue
			}
		}
		if c.Offline {
			var matches []models.CveMatch
			if m, ok := c.OfflineDB.(OfflineMatcher); ok && m.HasOSVNPM() {
				matches, _ = m.MatchNPM(comp.Name, comp.Version)
			}
			c.cache[key] = matches
			out[i] = ComponentMatch{Component: comp, Matches: matches}
			continue
		}

		dk := comp.Name + "\x00" + comp.Version
		if j, ok := jobIndex[dk]; ok {
			jobs[j].indices = append(jobs[j].indices, i)
			continue
		}
		jobIndex[dk] = len(jobs)
		jobs = append(jobs, queryTarget{
			q: query{
				Package: packageRef{Ecosystem: "npm", Name: comp.Name},
				Version: comp.Version,
			},
			indices: []int{i},
		})
	}

	if len(jobs) == 0 {
		return out, nil
	}

	c.Stats.OSVQueries = len(jobs)
	size := osvBatchSize()
	for start := 0; start < len(jobs); start += size {
		end := start + size
		if end > len(jobs) {
			end = len(jobs)
		}
		chunk := jobs[start:end]
		c.Stats.OSVChunks++

		queries := make([]query, len(chunk))
		for i, job := range chunk {
			queries[i] = job.q
		}
		results, err := c.queryBatchWithRetry(ctx, queries)
		if err != nil {
			return nil, err
		}
		if len(results) != len(chunk) {
			return nil, fmt.Errorf("osv batch: expected %d results, got %d", len(chunk), len(results))
		}
		for j, res := range results {
			for _, idx := range chunk[j].indices {
				comp := components[idx]
				matches := normalizeVulns(res.Vulns)
				key := cacheKey(comp)
				c.cache[key] = matches
				out[idx] = ComponentMatch{Component: comp, Matches: matches}
			}
		}
	}
	return out, nil
}

func osvBatchSize() int {
	v := os.Getenv("DEPFUSE_OSV_BATCH_SIZE")
	if v == "" {
		return 100
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 100
	}
	return n
}

func (c *Client) queryBatchWithRetry(ctx context.Context, queries []query) ([]result, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			wait := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
		results, err := c.queryBatchOnce(ctx, queries)
		if err == nil {
			return results, nil
		}
		lastErr = err
		if apiErr, ok := err.(*osvAPIError); ok && retryableOSVStatus(apiErr.StatusCode) {
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("osv batch failed after retries: %w", lastErr)
}

func retryableOSVStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func (c *Client) queryBatchOnce(ctx context.Context, queries []query) ([]result, error) {
	body, _ := json.Marshal(batchRequest{Queries: queries})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, &osvAPIError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	var br batchResponse
	if err := json.Unmarshal(data, &br); err != nil {
		return nil, err
	}
	return br.Results, nil
}

func normalizeVulns(vulns []osvVuln) []models.CveMatch {
	seen := map[string]bool{}
	var out []models.CveMatch
	for _, v := range vulns {
		cveID := canonicalCVE(v.ID, v.Aliases)
		if cveID == "" {
			cveID = v.ID // use OSV/GHSA id when no CVE alias exists
		}
		if seen[cveID] {
			continue
		}
		seen[cveID] = true
		var published time.Time
		if v.Published != "" {
			published, _ = time.Parse(time.RFC3339, v.Published)
		}
		severity := ""
		if len(v.Severity) > 0 {
			severity = v.Severity[0].Score
		}
		var refs []string
		for _, r := range v.References {
			if r.URL != "" {
				refs = append(refs, r.URL)
			}
		}
		var fixed []string
		for _, aff := range v.Affected {
			for _, rng := range aff.Ranges {
				if rng.Type == "GIT" {
					continue
				}
				for _, ev := range rng.Events {
					if ev.Fixed != "" {
						fixed = append(fixed, ev.Fixed)
					}
				}
			}
		}
		ghsa := ""
		if strings.HasPrefix(v.ID, "GHSA-") {
			ghsa = v.ID
		}
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "GHSA-") && ghsa == "" {
				ghsa = a
			}
		}
		out = append(out, models.CveMatch{
			CVEID:         cveID,
			OSVID:         v.ID,
			GHSAID:        ghsa,
			Aliases:       v.Aliases,
			Summary:       v.Summary,
			Severity:      severity,
			Published:     published,
			FixedVersions: fixed,
			References:    refs,
		})
	}
	return out
}

// EnrichFromQuery fills summary and fix versions using the OSV query API (batch responses omit these fields).
func (c *Client) EnrichFromQuery(ctx context.Context, comp models.Component, matches []models.CveMatch) error {
	if c.Offline || len(matches) == 0 {
		return nil
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	body, _ := json.Marshal(map[string]any{
		"package": map[string]string{"name": comp.Name, "ecosystem": "npm"},
		"version": comp.Version,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("osv query: http %d", resp.StatusCode)
	}
	var qr struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.Unmarshal(data, &qr); err != nil {
		return err
	}
	full := normalizeVulns(qr.Vulns)
	byID := map[string]models.CveMatch{}
	for _, m := range full {
		byID[m.CVEID] = m
		byID[m.OSVID] = m
		if m.GHSAID != "" {
			byID[m.GHSAID] = m
		}
		for _, a := range m.Aliases {
			byID[a] = m
		}
	}
	for i := range matches {
		keys := append([]string{matches[i].CVEID, matches[i].OSVID, matches[i].GHSAID}, matches[i].Aliases...)
		for _, k := range keys {
			if k == "" {
				continue
			}
			if src, ok := byID[k]; ok {
				if matches[i].Summary == "" && src.Summary != "" {
					matches[i].Summary = src.Summary
				}
				if len(matches[i].FixedVersions) == 0 && len(src.FixedVersions) > 0 {
					matches[i].FixedVersions = src.FixedVersions
				}
				if matches[i].Severity == "" && src.Severity != "" {
					matches[i].Severity = src.Severity
				}
				if matches[i].Published.IsZero() && !src.Published.IsZero() {
					matches[i].Published = src.Published
				}
				break
			}
		}
	}
	return nil
}

// QueryPackageCatalog returns all OSV advisories for a package (any version).
func (c *Client) QueryPackageCatalog(ctx context.Context, name string) ([]models.CveMatch, error) {
	if c.Offline || strings.TrimSpace(name) == "" {
		return nil, nil
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	body, _ := json.Marshal(map[string]any{
		"package": map[string]string{"name": name, "ecosystem": "npm"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("osv package catalog: http %d", resp.StatusCode)
	}
	var qr struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.Unmarshal(data, &qr); err != nil {
		return nil, err
	}
	return normalizeVulns(qr.Vulns), nil
}

// FormatUnaffectedPackageNote explains when catalog advisories exist but not for the resolved version.
func FormatUnaffectedPackageNote(comp models.Component, catalog []models.CveMatch) string {
	if len(catalog) == 0 {
		return ""
	}
	var examples []string
	fixHint := ""
	for _, m := range catalog {
		if id := m.AdvisoryID(); id != "" {
			examples = append(examples, id)
		}
		if fixHint == "" && len(m.FixedVersions) > 0 {
			fixHint = m.FixedVersions[0]
		}
		if len(examples) >= 3 {
			break
		}
	}
	target := fmt.Sprintf("%s@%s", comp.Name, comp.Version)
	msg := fmt.Sprintf("%d known advisory(ies) for %s (e.g. %s) do not affect %s",
		len(catalog), comp.Name, strings.Join(examples, ", "), target)
	if fixHint != "" {
		msg += fmt.Sprintf(" — patched in %s+", fixHint)
	}
	msg += fmt.Sprintf(". Pin a version: depfuse package %s@<version>", comp.Name)
	return msg
}

// CanonicalCVE resolves aliases to a canonical CVE ID.
func CanonicalCVE(id string, aliases []string) string {
	return canonicalCVE(id, aliases)
}

func canonicalCVE(id string, aliases []string) string {
	if cvePattern.MatchString(id) {
		return id
	}
	for _, a := range aliases {
		if cvePattern.MatchString(a) {
			return a
		}
	}
	return ""
}

func cacheKey(c models.Component) string {
	return c.Name + "@" + c.Version
}
