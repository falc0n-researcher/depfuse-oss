package intel

import (
	"encoding/json"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// SyncAliasesFromMatches upserts vuln_aliases from OSV match results.
func SyncAliasesFromMatches(s *Store, matches []models.CveMatch) error {
	for _, m := range matches {
		ids := append([]string{m.CVEID, m.OSVID, m.GHSAID}, m.Aliases...)
		canonical := PickCanonical(ids...)
		if canonical == "" {
			continue
		}
		if err := s.UpsertAlias(canonical, canonical); err != nil {
			return err
		}
		for _, id := range ids {
			if id != "" && id != canonical {
				if err := s.UpsertAlias(id, canonical); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// SyncAliasesFromOSVCache parses all cached OSV payloads into vuln_aliases.
func SyncAliasesFromOSVCache(s *Store) error {
	rows, err := s.db.Query(`SELECT payload FROM osv_cache`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return err
		}
		var matches []models.CveMatch
		if err := json.Unmarshal([]byte(payload), &matches); err != nil {
			continue
		}
		if err := SyncAliasesFromMatches(s, matches); err != nil {
			return err
		}
	}
	return rows.Err()
}
