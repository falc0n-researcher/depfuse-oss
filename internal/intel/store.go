package intel

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel/schema"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed intelligence snapshot.
type Store struct {
	db      *sql.DB
	path    string
	version string
}

// Open opens or creates an intelligence snapshot database.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return nil, err
	}
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.EnsureAuxTables(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.EnsurePerformanceIndexes(); err != nil {
		db.Close()
		return nil, err
	}
	s.version, _ = s.metaGet("snapshot_version")
	if s.version == "" {
		s.version, _ = s.metaGet("version")
	}
	return s, nil
}

func (s *Store) migrate() error {
	return schema.Migrate(
		func(stmt string) error {
			_, err := s.db.Exec(stmt)
			return err
		},
		s.metaGet,
		s.metaSet,
	)
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// Version returns snapshot version string.
func (s *Store) Version() string { return s.version }

// Hash returns a SHA256 hash of the database file.
func (s *Store) Hash() (string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8]), nil
}

func (s *Store) metaGet(key string) (string, error) {
	var val string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&val)
	return val, err
}

func (s *Store) metaSet(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// UpsertArtifact inserts legacy-format artifact (used by tests/seeds).
func (s *Store) UpsertArtifact(a models.RawArtifact) error {
	score := extractEPSS(a)
	rec := NormalizedRecord{
		CanonicalID: a.CVEID,
		Aliases:     []AliasInput{{Alias: a.CVEID, AliasType: InferAliasType(a.CVEID)}},
		Artifact: ArtifactInput{
			ID: a.ID, Source: a.Source, TrustClass: a.TrustClass, MaturityTag: a.MaturityTag,
			Title: a.Title, URL: a.URL, ObservedAt: a.ObservedAt, Extra: a.Metadata,
			EPSSScore: score, NucleiTemplate: a.Metadata["templateId"],
			MSFModule: a.Metadata["module"], EDBID: a.Metadata["edbId"],
		},
	}
	return s.UpsertNormalizedRecord(rec)
}

func extractEPSS(a models.RawArtifact) *float64 {
	if a.Metadata == nil {
		return nil
	}
	if s, ok := a.Metadata["score"]; ok {
		var f float64
		if _, err := fmt.Sscanf(s, "%f", &f); err == nil {
			return &f
		}
	}
	return nil
}

// GetOSVMatches implements match.OfflineReader.
func (s *Store) GetOSVMatches(ecosystem, name, version string) ([]models.CveMatch, bool) {
	var payload string
	err := s.db.QueryRow(`SELECT payload FROM osv_cache WHERE ecosystem=? AND name=? AND version=?`,
		ecosystem, name, version).Scan(&payload)
	if err != nil {
		return nil, false
	}
	var matches []models.CveMatch
	if err := json.Unmarshal([]byte(payload), &matches); err != nil {
		return nil, false
	}
	return matches, true
}

// PutOSVCache stores OSV matches for offline use.
func (s *Store) PutOSVCache(ecosystem, name, version string, matches []models.CveMatch) error {
	if matches == nil {
		matches = []models.CveMatch{}
	}
	payload, err := json.Marshal(matches)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.Exec(`
INSERT INTO osv_cache(ecosystem,name,version,fetched_at,payload) VALUES(?,?,?,?,?)
ON CONFLICT(ecosystem,name,version) DO UPDATE SET fetched_at=excluded.fetched_at, payload=excluded.payload`,
		ecosystem, name, version, now, string(payload))
	if err == nil {
		_ = SyncAliasesFromMatches(s, matches)
	}
	return err
}

// HomeDir is the local Depfuse data directory (~/.depfuse).
func HomeDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".depfuse")
}

// DefaultPath returns the default intelligence database location.
func DefaultPath() string {
	return filepath.Join(HomeDir(), "intel.db")
}

// CacheDir returns the default feed cache directory.
func CacheDir() string {
	return filepath.Join(HomeDir(), "cache")
}
