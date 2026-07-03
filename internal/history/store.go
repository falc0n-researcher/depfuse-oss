package history

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const maxHistoryPerInput = 10

// Store persists scan snapshots in the intel database.
type Store struct {
	Intel *intel.Store
}

func (s *Store) Save(inputHash, snapshotVersion string, at time.Time, snaps []models.HistorySnapshot) error {
	if s == nil || s.Intel == nil {
		return fmt.Errorf("history store: nil intel")
	}
	payload, err := json.Marshal(snaps)
	if err != nil {
		return err
	}
	db := s.Intel.DB()
	_, err = db.Exec(
		`INSERT INTO scan_history (snapshot_version, input_hash, scanned_at, findings_json) VALUES (?, ?, ?, ?)`,
		snapshotVersion, inputHash, at.UTC().Format(time.RFC3339), string(payload),
	)
	if err != nil {
		return fmt.Errorf("save scan history: %w", err)
	}
	return s.prune(inputHash)
}

func (s *Store) LoadPrevious(inputHash string) ([]models.HistorySnapshot, time.Time, error) {
	if s == nil || s.Intel == nil {
		return nil, time.Time{}, fmt.Errorf("history store: nil intel")
	}
	row := s.Intel.DB().QueryRow(
		`SELECT scanned_at, findings_json FROM scan_history WHERE input_hash = ? ORDER BY id DESC LIMIT 1`,
		inputHash,
	)
	var scannedAt, payload string
	if err := row.Scan(&scannedAt, &payload); err != nil {
		return nil, time.Time{}, err
	}
	at, err := time.Parse(time.RFC3339, scannedAt)
	if err != nil {
		at, _ = time.Parse(time.RFC3339Nano, scannedAt)
	}
	var snaps []models.HistorySnapshot
	if err := json.Unmarshal([]byte(payload), &snaps); err != nil {
		return nil, time.Time{}, err
	}
	return snaps, at, nil
}

func (s *Store) prune(inputHash string) error {
	_, err := s.Intel.DB().Exec(`
DELETE FROM scan_history WHERE input_hash = ? AND id NOT IN (
  SELECT id FROM scan_history WHERE input_hash = ? ORDER BY id DESC LIMIT ?
)`, inputHash, inputHash, maxHistoryPerInput)
	return err
}
