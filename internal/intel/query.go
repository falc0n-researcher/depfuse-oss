package intel

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// UpsertNormalizedRecord inserts vulnerability, aliases, and artifact.
func (s *Store) UpsertNormalizedRecord(rec NormalizedRecord) error {
	return upsertNormalizedRecord(s.db, rec)
}

// UpsertNormalizedRecords upserts many records in one transaction.
func (s *Store) UpsertNormalizedRecords(recs []NormalizedRecord) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	upserted := 0
	for _, rec := range recs {
		if err := upsertNormalizedRecord(tx, rec); err != nil {
			_ = tx.Rollback()
			return upserted, err
		}
		upserted++
	}
	return upserted, tx.Commit()
}

type sqlExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func upsertNormalizedRecord(db sqlExecer, rec NormalizedRecord) error {
	if rec.CanonicalID == "" {
		return fmt.Errorf("canonical id required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	vulnID := VulnID(rec.CanonicalID)

	_, err := db.Exec(`
INSERT INTO vulnerabilities(id, canonical_id, summary, published_at, created_at, updated_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
  summary=COALESCE(excluded.summary, vulnerabilities.summary),
  updated_at=excluded.updated_at`,
		vulnID, rec.CanonicalID, rec.Summary, "", now, now)
	if err != nil {
		return err
	}

	aliasSet := map[string]bool{}
	allAliases := append([]AliasInput{{Alias: rec.CanonicalID, AliasType: InferAliasType(rec.CanonicalID)}}, rec.Aliases...)
	for _, al := range allAliases {
		if al.Alias == "" || aliasSet[al.Alias] {
			continue
		}
		aliasSet[al.Alias] = true
		t := al.AliasType
		if t == "" {
			t = InferAliasType(al.Alias)
		}
		_, err := db.Exec(`
INSERT INTO vuln_aliases(alias, vulnerability_id, alias_type) VALUES(?,?,?)
ON CONFLICT(alias) DO UPDATE SET vulnerability_id=excluded.vulnerability_id`,
			al.Alias, vulnID, t)
		if err != nil {
			return err
		}
	}

	a := rec.Artifact
	if a.ID == "" {
		return nil
	}
	observed := a.ObservedAt
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	var extra sql.NullString
	if len(a.Extra) > 0 {
		b, _ := json.Marshal(a.Extra)
		extra = sql.NullString{String: string(b), Valid: true}
	}
	var epss sql.NullFloat64
	if a.EPSSScore != nil {
		epss = sql.NullFloat64{Float64: *a.EPSSScore, Valid: true}
	}
	var stars sql.NullInt64
	if a.PoCStars != nil {
		stars = sql.NullInt64{Int64: int64(*a.PoCStars), Valid: true}
	}

	_, err = db.Exec(`
INSERT INTO artifacts(
  id, vulnerability_id, source, trust_class, maturity_tag, title, url, observed_at, feed_run_id,
  epss_score, nuclei_template, msf_module, edb_id, poc_repo, poc_stars, extra)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
  trust_class=excluded.trust_class, maturity_tag=excluded.maturity_tag,
  title=excluded.title, url=excluded.url, observed_at=excluded.observed_at,
  feed_run_id=excluded.feed_run_id, epss_score=excluded.epss_score,
  nuclei_template=excluded.nuclei_template, msf_module=excluded.msf_module,
  edb_id=excluded.edb_id, poc_repo=excluded.poc_repo, poc_stars=excluded.poc_stars,
  extra=excluded.extra`,
		a.ID, vulnID, string(a.Source), string(a.TrustClass), string(a.MaturityTag),
		a.Title, a.URL, observed.Format(time.RFC3339), nullStr(a.FeedRunID),
		epss, nullStr(a.NucleiTemplate), nullStr(a.MSFModule), nullStr(a.EDBID),
		nullStr(a.PoCRepo), stars, extra)
	return err
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// ArtifactsForAnyID returns artifacts matching any alias or canonical id.
func (s *Store) ArtifactsForAnyID(ids ...string) ([]models.RawArtifact, error) {
	unique := dedupeIDs(ids...)
	if len(unique) == 0 {
		return nil, nil
	}

	weapon, err := s.artifactsForAliases(unique, "KEV", "VULNCHECK_XDB", "NUCLEI", "METASPLOIT", "EXPLOITDB", "POC_GITHUB")
	if err != nil {
		return nil, err
	}
	epss, err := s.epssForAliases(unique)
	if err != nil {
		return nil, err
	}
	if len(epss) == 0 {
		return weapon, nil
	}
	return append(weapon, epss...), nil
}

func dedupeIDs(ids ...string) []string {
	seen := map[string]bool{}
	var unique []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		unique = append(unique, id)
	}
	return unique
}

func (s *Store) artifactsForAliases(ids []string, sources ...string) ([]models.RawArtifact, error) {
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]

	srcPH := strings.Repeat("?,", len(sources))
	srcPH = srcPH[:len(srcPH)-1]

	query := fmt.Sprintf(`
SELECT DISTINCT a.id, v.canonical_id, a.source, a.trust_class, a.maturity_tag,
       a.title, a.url, a.observed_at, a.extra, a.epss_score, a.nuclei_template, a.msf_module, a.edb_id
FROM artifacts a
JOIN vulnerabilities v ON v.id = a.vulnerability_id
JOIN vuln_aliases va ON va.vulnerability_id = v.id
WHERE va.alias IN (%s) AND a.source IN (%s)`, placeholders, srcPH)

	args := make([]interface{}, 0, len(ids)+len(sources))
	for _, id := range ids {
		args = append(args, id)
	}
	for _, src := range sources {
		args = append(args, src)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanArtifactRowsV2(rows)
}

func (s *Store) epssForAliases(ids []string) ([]models.RawArtifact, error) {
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]

	query := fmt.Sprintf(`
SELECT a.id, v.canonical_id, a.source, a.trust_class, a.maturity_tag,
       a.title, a.url, a.observed_at, a.extra, a.epss_score, a.nuclei_template, a.msf_module, a.edb_id
FROM artifacts a
JOIN vulnerabilities v ON v.id = a.vulnerability_id
WHERE a.source = 'EPSS' AND v.id IN (
  SELECT DISTINCT va.vulnerability_id FROM vuln_aliases va WHERE va.alias IN (%s)
)
LIMIT 1`, placeholders)

	args := make([]interface{}, len(ids))
	for i, id := range ids {
		args[i] = id
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanArtifactRowsV2(rows)
}

// ArtifactsForCVE is kept for compatibility; delegates to ArtifactsForAnyID.
func (s *Store) ArtifactsForCVE(cveID string) ([]models.RawArtifact, error) {
	return s.ArtifactsForAnyID(cveID)
}

func scanArtifactRowsV2(rows *sql.Rows) ([]models.RawArtifact, error) {
	var out []models.RawArtifact
	for rows.Next() {
		var a models.RawArtifact
		var source, trust, maturity, observed string
		var extraJSON sql.NullString
		var epss sql.NullFloat64
		var nuclei, msf, edb sql.NullString
		if err := rows.Scan(&a.ID, &a.CVEID, &source, &trust, &maturity, &a.Title, &a.URL, &observed, &extraJSON, &epss, &nuclei, &msf, &edb); err != nil {
			return nil, err
		}
		a.Source = models.Source(source)
		a.TrustClass = models.TrustClass(trust)
		a.MaturityTag = models.MaturityTag(maturity)
		a.ObservedAt, _ = time.Parse(time.RFC3339, observed)
		a.Metadata = map[string]string{}
		if extraJSON.Valid && extraJSON.String != "" {
			_ = json.Unmarshal([]byte(extraJSON.String), &a.Metadata)
		}
		if epss.Valid {
			a.Metadata["score"] = fmt.Sprintf("%g", epss.Float64)
		}
		if nuclei.Valid {
			a.Metadata["templateId"] = nuclei.String
		}
		if msf.Valid {
			a.Metadata["module"] = msf.String
		}
		if edb.Valid {
			a.Metadata["edbId"] = edb.String
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpsertAlias links an alias to a canonical vulnerability.
func (s *Store) UpsertAlias(alias, canonicalID string) error {
	if alias == "" || canonicalID == "" {
		return nil
	}
	vulnID := VulnID(canonicalID)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
INSERT INTO vulnerabilities(id, canonical_id, created_at, updated_at) VALUES(?,?,?,?)
ON CONFLICT(id) DO NOTHING`, vulnID, canonicalID, now, now)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO vuln_aliases(alias, vulnerability_id, alias_type) VALUES(?,?,?)
ON CONFLICT(alias) DO UPDATE SET vulnerability_id=excluded.vulnerability_id`,
		alias, vulnID, InferAliasType(alias))
	return err
}

// HasData returns true if the DB has at least one artifact.
func (s *Store) HasData() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM artifacts`).Scan(&n)
	return n > 0, err
}

// FeedStats holds collector statistics.
type FeedStats struct {
	Feeds []FeedStatRow
	Total int
}

// FeedStatRow is one feed's status.
type FeedStatRow struct {
	Name          string
	LastSuccess   string
	LastError     string
	ArtifactCount int
}

// Stats returns feed and artifact statistics.
func (s *Store) Stats() (FeedStats, error) {
	// OSV_NPM stores into the dedicated osv_npm match index, not the artifacts
	// table, so count that table for it; all other feeds populate artifacts.
	rows, err := s.db.Query(`
SELECT f.name, COALESCE(f.last_success_at,''), COALESCE(f.last_error,''),
       CASE WHEN f.name='OSV_NPM' THEN (SELECT COUNT(*) FROM osv_npm)
            ELSE (SELECT COUNT(*) FROM artifacts a JOIN feed_runs r ON a.feed_run_id=r.id WHERE r.feed_name=f.name)
       END
FROM feeds f ORDER BY f.name`)
	if err != nil {
		return FeedStats{}, err
	}
	defer rows.Close()
	var stats FeedStats
	for rows.Next() {
		var r FeedStatRow
		if err := rows.Scan(&r.Name, &r.LastSuccess, &r.LastError, &r.ArtifactCount); err != nil {
			return stats, err
		}
		stats.Feeds = append(stats.Feeds, r)
	}
	// Total mirrors the per-feed breakdown: artifacts table plus the OSV_NPM
	// match index, which lives in its own table.
	_ = s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM artifacts) + (SELECT COUNT(*) FROM osv_npm)`).Scan(&stats.Total)
	return stats, rows.Err()
}

// BeginFeedRun starts a feed run audit record.
func (s *Store) BeginFeedRun(id, feedName string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
INSERT INTO feed_runs(id, feed_name, started_at, status) VALUES(?,?,?,?)`,
		id, feedName, now, "running")
	return err
}

// FinishFeedRun completes a feed run audit record.
func (s *Store) FinishFeedRun(id, status string, fetched, upserted int, httpStatus int, contentSHA, errMsg string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
UPDATE feed_runs SET finished_at=?, status=?, records_fetched=?, records_upserted=?,
  http_status=?, content_sha256=?, error=? WHERE id=?`,
		now, status, fetched, upserted, httpStatus, contentSHA, errMsg, id)
	if err != nil {
		return err
	}
	if status == "success" || status == "partial" {
		_, _ = s.db.Exec(`UPDATE feeds SET last_success_at=?, last_error='' WHERE name=(SELECT feed_name FROM feed_runs WHERE id=?)`, now, id)
	} else if errMsg != "" {
		_, _ = s.db.Exec(`UPDATE feeds SET last_error=? WHERE name=(SELECT feed_name FROM feed_runs WHERE id=?)`, errMsg, id)
	}
	return nil
}

// EnsureFeeds registers default feed catalog entries.
func (s *Store) EnsureFeeds() error {
	feeds := []struct {
		name, desc, url, trust, policy string
	}{
		{"KEV", "VulnCheck Known Exploited Vulnerabilities (Community)", "https://api.vulncheck.com/v3/backup/vulncheck-kev", "authoritative", "daily"},
		{"EPSS", "FIRST EPSS scores", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", "medium", "daily"},
		{"NUCLEI", "ProjectDiscovery Nuclei templates", "https://github.com/projectdiscovery/nuclei-templates", "high", "weekly"},
		{"METASPLOIT", "Metasploit module metadata", "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json", "high", "weekly"},
		{"EXPLOITDB", "Exploit-DB index CSV", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv", "medium", "weekly"},
		{"POC_GITHUB", "GitHub PoC repository search (metadata only)", "https://api.github.com/search/repositories", "low", "weekly"},
		{"OSV_NPM", "OSV npm advisory export (offline match index)", "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip", "authoritative", "daily"},
	}
	for _, f := range feeds {
		_, err := s.db.Exec(`
INSERT INTO feeds(name, description, url, trust_class, refresh_policy, enabled)
VALUES(?,?,?,?,?,1) ON CONFLICT(name) DO UPDATE SET
  description=excluded.description,
  url=excluded.url,
  trust_class=excluded.trust_class`,
			f.name, f.desc, f.url, f.trust, f.policy)
		if err != nil {
			return err
		}
	}
	return nil
}

// SetCollectedMeta updates snapshot version metadata after collect.
func (s *Store) SetCollectedMeta() error {
	version := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if prev, err := s.metaGet("collected_at"); err == nil && prev != "" {
		_ = s.metaSet("previous_collected_at", prev)
	}
	if err := s.metaSet("snapshot_version", version); err != nil {
		return err
	}
	if err := s.metaSet("collected_at", version); err != nil {
		return err
	}
	s.version = version
	return nil
}

// CollectedAt returns the timestamp of the last successful collect.
func (s *Store) CollectedAt() (time.Time, error) {
	val, err := s.metaGet("collected_at")
	if err != nil || val == "" {
		return time.Time{}, err
	}
	if t, err := time.Parse(time.RFC3339, val); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid collected_at %q", val)
}

// PreviousCollectedAt returns the collect timestamp before the most recent one.
func (s *Store) PreviousCollectedAt() (time.Time, error) {
	val, err := s.metaGet("previous_collected_at")
	if err != nil || val == "" {
		return time.Time{}, err
	}
	if t, err := time.Parse(time.RFC3339, val); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid previous_collected_at %q", val)
}

// CVEsWithArtifacts lists canonical CVE ids that have weaponization or EPSS artifacts.
func (s *Store) CVEsWithArtifacts() ([]string, error) {
	rows, err := s.db.Query(`
SELECT DISTINCT v.canonical_id
FROM vulnerabilities v
JOIN artifacts a ON a.vulnerability_id = v.id
WHERE v.canonical_id LIKE 'CVE-%'
ORDER BY v.canonical_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// EnsurePerformanceIndexes adds indexes safe to apply on existing databases.
func (s *Store) EnsurePerformanceIndexes() error {
	_, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_vuln_aliases_alias ON vuln_aliases(alias)`)
	return err
}

// LastFeedContentSHA returns the content hash from the latest successful feed run.
func (s *Store) LastFeedContentSHA(feedName string) (string, error) {
	var hash sql.NullString
	err := s.db.QueryRow(`
SELECT content_sha256 FROM feed_runs
WHERE feed_name=? AND status='success' AND COALESCE(content_sha256,'') != ''
ORDER BY finished_at DESC LIMIT 1`, feedName).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if hash.Valid {
		return hash.String, nil
	}
	return "", nil
}

// DB exposes the underlying database for tests.
func (s *Store) DB() *sql.DB { return s.db }
