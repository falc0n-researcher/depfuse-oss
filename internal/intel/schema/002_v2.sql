-- Depfuse Intelligence DB schema v2
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id            TEXT PRIMARY KEY,
  canonical_id  TEXT NOT NULL UNIQUE,
  summary       TEXT,
  published_at  TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vuln_aliases (
  alias            TEXT PRIMARY KEY,
  vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  alias_type       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vuln_aliases_vuln ON vuln_aliases(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_vuln_aliases_alias ON vuln_aliases(alias);

CREATE TABLE IF NOT EXISTS feeds (
  name            TEXT PRIMARY KEY,
  description     TEXT,
  url             TEXT,
  trust_class     TEXT NOT NULL,
  refresh_policy  TEXT NOT NULL DEFAULT 'always',
  enabled         INTEGER NOT NULL DEFAULT 1,
  last_success_at TEXT,
  last_error      TEXT
);

CREATE TABLE IF NOT EXISTS feed_runs (
  id                TEXT PRIMARY KEY,
  feed_name         TEXT NOT NULL REFERENCES feeds(name),
  started_at        TEXT NOT NULL,
  finished_at       TEXT,
  status            TEXT NOT NULL,
  records_fetched   INTEGER DEFAULT 0,
  records_upserted  INTEGER DEFAULT 0,
  http_status       INTEGER,
  content_sha256    TEXT,
  error             TEXT
);
CREATE INDEX IF NOT EXISTS idx_feed_runs_feed ON feed_runs(feed_name, started_at DESC);

CREATE TABLE IF NOT EXISTS artifacts (
  id               TEXT PRIMARY KEY,
  vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  source           TEXT NOT NULL,
  trust_class      TEXT NOT NULL,
  maturity_tag     TEXT,
  title            TEXT NOT NULL,
  url              TEXT,
  observed_at      TEXT NOT NULL,
  feed_run_id      TEXT REFERENCES feed_runs(id),
  epss_score       REAL,
  nuclei_template  TEXT,
  msf_module       TEXT,
  edb_id           TEXT,
  poc_repo         TEXT,
  poc_stars        INTEGER,
  extra            TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_vuln ON artifacts(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_source ON artifacts(source);
CREATE INDEX IF NOT EXISTS idx_artifacts_vuln_source ON artifacts(vulnerability_id, source);

CREATE TABLE IF NOT EXISTS osv_cache (
  ecosystem  TEXT NOT NULL,
  name       TEXT NOT NULL,
  version    TEXT NOT NULL,
  fetched_at TEXT NOT NULL DEFAULT '',
  payload    TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, version)
);

CREATE TABLE IF NOT EXISTS scan_history (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_version TEXT NOT NULL,
  input_hash       TEXT NOT NULL,
  scanned_at       TEXT NOT NULL,
  findings_json    TEXT NOT NULL
);

CREATE VIEW IF NOT EXISTS v_vuln_signals AS
SELECT v.canonical_id, va.alias,
       MAX(CASE WHEN a.source='KEV' THEN 1 ELSE 0 END) AS kev,
       MAX(CASE WHEN a.source='NUCLEI' THEN 1 ELSE 0 END) AS nuclei,
       MAX(a.epss_score) AS epss,
       COUNT(a.id) AS artifact_count
FROM vulnerabilities v
JOIN vuln_aliases va ON va.vulnerability_id = v.id
LEFT JOIN artifacts a ON a.vulnerability_id = v.id
GROUP BY v.id, va.alias;
