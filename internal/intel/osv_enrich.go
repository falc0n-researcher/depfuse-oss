package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const osvVulnURL = "https://api.osv.dev/v1/vulns/"

type osvVulnFull struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Published  string         `json:"published"`
	Aliases    []string       `json:"aliases"`
	Severity   []osvSeverity  `json:"severity"`
	Affected   []osvAffected  `json:"affected"`
	References []osvReference `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed string `json:"fixed"`
}

type osvReference struct {
	URL string `json:"url"`
}

// EnrichVulnRecords fetches full OSV advisory data for exploit-risk CVEs during collect.
func EnrichVulnRecords(ctx context.Context, s *Store) (int, error) {
	if err := SyncAliasesFromOSVCache(s); err != nil {
		return 0, err
	}
	cves, err := s.WeaponizationCVEs()
	if err != nil {
		return 0, err
	}
	return enrichVulnRecords(ctx, s, osvVulnURL, cves)
}

// EnrichVulnRecordsWithBaseURL is for tests.
func EnrichVulnRecordsWithBaseURL(ctx context.Context, s *Store, baseURL string, cves []string) (int, error) {
	return enrichVulnRecords(ctx, s, baseURL, cves)
}

func enrichVulnRecords(ctx context.Context, s *Store, baseURL string, cves []string) (int, error) {
	if err := s.EnsureAuxTables(); err != nil {
		return 0, err
	}
	if len(cves) == 0 {
		return 0, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	workers := 8
	type job struct{ cve string }
	jobs := make(chan job, workers*2)
	var wg sync.WaitGroup
	var mu sync.Mutex
	synced := 0
	var firstErr error

	recordErr := func(e error) {
		mu.Lock()
		defer mu.Unlock()
		if firstErr == nil {
			firstErr = e
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				payload, err := fetchOSVVuln(ctx, client, baseURL, j.cve)
				if err != nil {
					recordErr(err)
					continue
				}
				if len(payload) == 0 {
					continue
				}
				if err := s.storeOSVVulnPayload(j.cve, payload); err != nil {
					recordErr(err)
					continue
				}
				mu.Lock()
				synced++
				mu.Unlock()
			}
		}()
	}

loop:
	for _, cve := range cves {
		select {
		case <-ctx.Done():
			break loop
		case jobs <- job{cve: cve}:
		}
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil && synced == 0 {
		return synced, firstErr
	}
	return synced, nil
}

func fetchOSVVuln(ctx context.Context, client *http.Client, baseURL, id string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return []byte(`{"id":""}`), nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("osv vuln %s: http %d", id, resp.StatusCode)
	}
	return body, nil
}

func (s *Store) storeOSVVulnPayload(fetchID string, payload []byte) error {
	var rec osvVulnFull
	if err := json.Unmarshal(payload, &rec); err != nil {
		return err
	}
	if rec.ID == "" {
		return nil
	}

	ids := append([]string{rec.ID}, rec.Aliases...)
	canonical := PickCanonical(ids...)
	if canonical == "" {
		canonical = rec.ID
	}

	match := mergeOSVPayload(models.CveMatch{CVEID: canonical, OSVID: rec.ID}, payload)
	if err := SyncAliasesFromMatches(s, []models.CveMatch{match}); err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	published := rec.Published
	_, err := s.db.Exec(`
INSERT INTO vulnerabilities(id, canonical_id, summary, published_at, created_at, updated_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
  summary=COALESCE(excluded.summary, vulnerabilities.summary),
  published_at=COALESCE(excluded.published_at, vulnerabilities.published_at),
  updated_at=excluded.updated_at`,
		VulnID(canonical), canonical, nullIfEmpty(match.Summary), nullIfEmpty(published), now, now)
	if err != nil {
		return err
	}

	if err := s.putOSVVulnCache(canonical, payload); err != nil {
		return err
	}
	if fetchID != canonical {
		_ = s.putOSVVulnCache(fetchID, payload)
	}
	for _, alias := range rec.Aliases {
		if alias != canonical && alias != fetchID {
			_ = s.putOSVVulnCache(alias, payload)
		}
	}
	return nil
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// EnrichCveMatch fills advisory fields from the local OSV cache or live API.
func EnrichCveMatch(ctx context.Context, s *Store, m *models.CveMatch, offline bool) error {
	_ = PatchCveMatch(s, m)

	merged := false
	for _, id := range enrichmentLookupIDs(*m) {
		payload, ok := s.lookupOSVVulnPayload(id)
		if !ok || len(payload) == 0 {
			continue
		}
		*m = mergeOSVPayload(*m, payload)
		merged = true
	}

	if len(m.FixedVersions) == 0 || strings.TrimSpace(m.Summary) == "" {
		for _, id := range enrichmentLookupIDs(*m) {
			if len(m.FixedVersions) > 0 && strings.TrimSpace(m.Summary) != "" {
				break
			}
			client := &http.Client{Timeout: 30 * time.Second}
			fetched, err := fetchOSVVuln(ctx, client, osvVulnURL, id)
			if err != nil || len(fetched) == 0 {
				continue
			}
			if err := s.storeOSVVulnPayload(id, fetched); err != nil {
				continue
			}
			*m = mergeOSVPayload(*m, fetched)
			merged = true
		}
	}

	if !merged {
		return nil
	}
	return nil
}

// enrichmentLookupIDs returns OSV cache keys to consult. GHSA records carry npm
// semver fix ranges; CVE-only records often list GIT commit ranges only.
func enrichmentLookupIDs(m models.CveMatch) []string {
	seen := map[string]bool{}
	var ids []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if m.GHSAID != "" {
		add(m.GHSAID)
	}
	for _, a := range m.Aliases {
		if strings.HasPrefix(a, "GHSA-") {
			add(a)
		}
	}
	add(m.CVEID)
	add(m.OSVID)
	for _, a := range m.Aliases {
		add(a)
	}
	return ids
}

func bestOSVLookupID(m models.CveMatch) string {
	if cvePattern.MatchString(m.CVEID) {
		return m.CVEID
	}
	if m.GHSAID != "" {
		return m.GHSAID
	}
	if m.OSVID != "" {
		return m.OSVID
	}
	for _, a := range m.Aliases {
		if strings.HasPrefix(a, "GHSA-") || strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return m.CVEID
}

func (s *Store) lookupOSVVulnPayload(ids ...string) ([]byte, bool) {
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if payload, err := s.getOSVVulnCache(id); err == nil && len(payload) > 0 {
			return payload, true
		}
		canonical, err := s.canonicalForAlias(id)
		if err != nil || canonical == "" {
			continue
		}
		if payload, err := s.getOSVVulnCache(canonical); err == nil && len(payload) > 0 {
			return payload, true
		}
	}
	return nil, false
}

func (s *Store) canonicalForAlias(alias string) (string, error) {
	var canonical string
	err := s.db.QueryRow(`
SELECT v.canonical_id FROM vuln_aliases va
JOIN vulnerabilities v ON v.id = va.vulnerability_id
WHERE va.alias = ?`, alias).Scan(&canonical)
	if err != nil {
		return "", err
	}
	return canonical, nil
}

func mergeOSVPayload(m models.CveMatch, payload []byte) models.CveMatch {
	var v osvVulnFull
	if err := json.Unmarshal(payload, &v); err != nil || v.ID == "" {
		return m
	}

	if v.Summary != "" {
		m.Summary = v.Summary
	}
	if v.Details != "" {
		m.Details = v.Details
	}
	if v.Published != "" {
		if t, err := time.Parse(time.RFC3339, v.Published); err == nil {
			m.Published = t
		}
	}
	if len(v.Severity) > 0 && v.Severity[0].Score != "" {
		m.Severity = v.Severity[0].Score
	}

	aliasSet := map[string]bool{}
	for _, a := range append(m.Aliases, v.Aliases...) {
		if a != "" {
			aliasSet[a] = true
		}
	}
	if m.CVEID != "" {
		aliasSet[m.CVEID] = true
	}
	if cve := PickCanonical(append(v.Aliases, v.ID)...); cve != "" {
		m.CVEID = cve
		aliasSet[cve] = true
	}
	m.OSVID = v.ID
	if strings.HasPrefix(v.ID, "GHSA-") {
		m.GHSAID = v.ID
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "GHSA-") {
			m.GHSAID = a
			break
		}
	}
	m.Aliases = make([]string, 0, len(aliasSet))
	for a := range aliasSet {
		m.Aliases = append(m.Aliases, a)
	}

	fixedSet := map[string]bool{}
	for _, f := range m.FixedVersions {
		fixedSet[f] = true
	}
	for _, aff := range v.Affected {
		for _, rng := range aff.Ranges {
			if rng.Type == "GIT" {
				continue
			}
			for _, ev := range rng.Events {
				if ev.Fixed != "" && isVersionFix(ev.Fixed) {
					fixedSet[ev.Fixed] = true
				}
			}
		}
	}
	m.FixedVersions = m.FixedVersions[:0]
	for f := range fixedSet {
		m.FixedVersions = append(m.FixedVersions, f)
	}

	pkgMap := map[string]models.AffectedPackage{}
	for _, aff := range v.Affected {
		if aff.Package.Name == "" {
			continue
		}
		key := aff.Package.Ecosystem + "\x00" + aff.Package.Name
		fix := fixedVersionForAffected(aff)
		if existing, ok := pkgMap[key]; ok {
			if fix != "" && existing.FixedVersion == "" {
				existing.FixedVersion = fix
				pkgMap[key] = existing
			}
			continue
		}
		pkgMap[key] = models.AffectedPackage{
			Name:         aff.Package.Name,
			Ecosystem:    aff.Package.Ecosystem,
			FixedVersion: fix,
		}
	}
	m.AffectedPackages = m.AffectedPackages[:0]
	for _, p := range pkgMap {
		m.AffectedPackages = append(m.AffectedPackages, p)
	}

	refSet := map[string]bool{}
	for _, r := range m.References {
		refSet[r] = true
	}
	for _, r := range v.References {
		if r.URL != "" {
			refSet[r.URL] = true
		}
	}
	m.References = m.References[:0]
	for u := range refSet {
		m.References = append(m.References, u)
	}
	return m
}

func fixedVersionForAffected(aff osvAffected) string {
	for _, rng := range aff.Ranges {
		if rng.Type == "GIT" {
			continue
		}
		for _, ev := range rng.Events {
			if ev.Fixed != "" && isVersionFix(ev.Fixed) {
				return ev.Fixed
			}
		}
	}
	return ""
}

func isVersionFix(fixed string) bool {
	if fixed == "" {
		return false
	}
	if len(fixed) >= 40 && !strings.Contains(fixed, ".") {
		return false
	}
	return fixed[0] >= '0' && fixed[0] <= '9'
}

func (s *Store) getOSVVulnCache(id string) ([]byte, error) {
	var payload string
	err := s.db.QueryRow(`SELECT payload FROM osv_vuln_cache WHERE cve=?`, id).Scan(&payload)
	if err != nil {
		return nil, err
	}
	return []byte(payload), nil
}

func (s *Store) putOSVVulnCache(id string, payload []byte) error {
	if len(payload) == 0 || id == "" {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
INSERT INTO osv_vuln_cache(cve, fetched_at, payload) VALUES(?,?,?)
ON CONFLICT(cve) DO UPDATE SET fetched_at=excluded.fetched_at, payload=excluded.payload`,
		id, now, string(payload))
	return err
}
