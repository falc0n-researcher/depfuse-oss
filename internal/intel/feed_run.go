package intel

import (
	"fmt"
	"time"
)

// AbortRunningFeedRuns marks in-flight feed runs as aborted.
func (s *Store) AbortRunningFeedRuns(reason string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`
UPDATE feed_runs SET status='aborted', finished_at=?, error=?
WHERE status='running'`, now, reason)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// WeaponizationCVEs returns distinct CVE ids referenced by non-EPSS feeds.
func (s *Store) WeaponizationCVEs() ([]string, error) {
	rows, err := s.db.Query(`
SELECT DISTINCT v.canonical_id
FROM vulnerabilities v
JOIN artifacts a ON a.vulnerability_id = v.id
WHERE a.source IN ('KEV','NUCLEI','METASPLOIT','EXPLOITDB')
ORDER BY v.canonical_id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cves []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, err
		}
		cves = append(cves, cve)
	}
	return cves, rows.Err()
}

// EnsureAuxTables creates additive schema objects not tied to a major migration.
func (s *Store) EnsureAuxTables() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS osv_vuln_cache (
  cve        TEXT PRIMARY KEY,
  fetched_at TEXT NOT NULL,
  payload    TEXT NOT NULL
)`)
	if err != nil {
		return fmt.Errorf("osv_vuln_cache: %w", err)
	}
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS osv_npm (
  package     TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  payload     TEXT NOT NULL,
  PRIMARY KEY (package, advisory_id)
)`); err != nil {
		return fmt.Errorf("osv_npm: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_osv_npm_pkg ON osv_npm(package)`); err != nil {
		return fmt.Errorf("osv_npm index: %w", err)
	}
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS osv_npm_alias (
  alias       TEXT NOT NULL,
  package     TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  PRIMARY KEY (alias, package, advisory_id)
)`); err != nil {
		return fmt.Errorf("osv_npm_alias: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_osv_npm_alias ON osv_npm_alias(alias)`); err != nil {
		return fmt.Errorf("osv_npm_alias index: %w", err)
	}
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS package_meta (
  name              TEXT PRIMARY KEY,
  description       TEXT,
  license           TEXT,
  homepage          TEXT,
  weekly_downloads  INTEGER NOT NULL DEFAULT 0,
  popularity        TEXT,
  fetched_at        TEXT NOT NULL
)`); err != nil {
		return fmt.Errorf("package_meta: %w", err)
	}
	return nil
}
