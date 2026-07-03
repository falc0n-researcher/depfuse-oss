package intel

import (
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// PatchCveMatch fills CVE and alias fields from the vuln_aliases table.
func PatchCveMatch(s *Store, m *models.CveMatch) error {
	ids := append([]string{m.CVEID, m.OSVID, m.GHSAID}, m.Aliases...)
	aliases, canonical, err := s.lookupAliasSet(ids...)
	if err != nil {
		return err
	}
	if canonical == "" {
		return nil
	}
	seen := map[string]bool{}
	var merged []string
	for _, a := range append(aliases, ids...) {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		merged = append(merged, a)
	}
	m.Aliases = merged
	if strings.HasPrefix(canonical, "CVE-") {
		if strings.HasPrefix(m.CVEID, "GHSA-") && m.GHSAID == "" {
			m.GHSAID = m.CVEID
		}
		if !strings.HasPrefix(m.CVEID, "CVE-") {
			m.CVEID = canonical
		}
	}
	return nil
}

func (s *Store) lookupAliasSet(ids ...string) ([]string, string, error) {
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		var vulnID string
		err := s.db.QueryRow(`SELECT vulnerability_id FROM vuln_aliases WHERE alias=?`, id).Scan(&vulnID)
		if err != nil {
			continue
		}
		var canonical string
		if err := s.db.QueryRow(`SELECT canonical_id FROM vulnerabilities WHERE id=?`, vulnID).Scan(&canonical); err != nil {
			continue
		}
		rows, err := s.db.Query(`SELECT alias FROM vuln_aliases WHERE vulnerability_id=?`, vulnID)
		if err != nil {
			return nil, canonical, err
		}
		var out []string
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				rows.Close()
				return out, canonical, err
			}
			out = append(out, a)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return out, canonical, err
		}
		rows.Close()
		return out, canonical, nil
	}
	return nil, "", nil
}
