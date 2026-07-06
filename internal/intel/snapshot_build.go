package intel

import "fmt"

// WeaponizedEPSSThreshold is the EPSS exploitation-likelihood score at or above
// which a signal-free advisory is still worth watching. It mirrors the Watch
// boundary in internal/classify, so a snapshot pruned at this threshold
// reproduces every non-Quiet verdict.
const WeaponizedEPSSThreshold = 0.05

// SnapshotStats summarizes a PruneToWeaponized run.
type SnapshotStats struct {
	AdvisoriesKept int
	VulnsKept      int
}

// PruneToWeaponized reduces a full offline index to only the npm advisories
// whose CVE/GHSA aliases carry an exploit signal (KEV, Nuclei, Metasploit,
// Exploit-DB, public PoC) or an EPSS score at/above epssThreshold — exactly the
// set Depfuse would not classify Quiet. The pruned DB therefore reproduces
// every non-Quiet verdict offline at a fraction of the size. Signal rows for
// dropped advisories and all online/runtime caches are removed, then the file
// is VACUUMed. It is the builder for the embedded first-run snapshot.
func (s *Store) PruneToWeaponized(epssThreshold float64) (SnapshotStats, error) {
	var st SnapshotStats

	tx, err := s.db.Begin()
	if err != nil {
		return st, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Weaponized advisory ids: osv_npm advisories whose alias maps (via the
	// signal-side alias table) to a vulnerability carrying an exploit artifact
	// or a high-enough EPSS score.
	if _, err := tx.Exec(`
CREATE TEMP TABLE weaponized_adv AS
SELECT DISTINCT na.advisory_id
FROM osv_npm_alias na
JOIN vuln_aliases va ON va.alias = na.alias
JOIN artifacts a ON a.vulnerability_id = va.vulnerability_id
WHERE a.source IN ('KEV','NUCLEI','METASPLOIT','EXPLOITDB','POC_GITHUB')
   OR (a.source = 'EPSS' AND a.epss_score >= ?)`, epssThreshold); err != nil {
		return st, fmt.Errorf("compute weaponized set: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM osv_npm WHERE advisory_id NOT IN (SELECT advisory_id FROM weaponized_adv)`); err != nil {
		return st, fmt.Errorf("prune osv_npm: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM osv_npm_alias WHERE advisory_id NOT IN (SELECT advisory_id FROM osv_npm)`); err != nil {
		return st, fmt.Errorf("prune osv_npm_alias: %w", err)
	}

	// Keep only signal rows for vulnerabilities still referenced by the pruned
	// index; ON DELETE CASCADE (foreign_keys is enabled in the DSN) clears their
	// artifacts and aliases.
	if _, err := tx.Exec(`
DELETE FROM vulnerabilities WHERE id NOT IN (
  SELECT DISTINCT va.vulnerability_id
  FROM vuln_aliases va
  JOIN osv_npm_alias na ON na.alias = va.alias
)`); err != nil {
		return st, fmt.Errorf("prune vulnerabilities: %w", err)
	}

	// Online/runtime caches don't belong in a shipped snapshot.
	for _, t := range []string{"osv_cache", "osv_vuln_cache", "scan_history", "feed_runs"} {
		_, _ = tx.Exec("DELETE FROM " + t) //nolint:errcheck // tables may be absent in older DBs
	}

	if err := tx.QueryRow(`SELECT COUNT(*) FROM osv_npm`).Scan(&st.AdvisoriesKept); err != nil {
		return st, err
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM vulnerabilities`).Scan(&st.VulnsKept); err != nil {
		return st, err
	}
	if _, err := tx.Exec(`DROP TABLE weaponized_adv`); err != nil {
		return st, err
	}
	if err := tx.Commit(); err != nil {
		return st, err
	}
	if err := s.metaSet("weaponized_only", "true"); err != nil {
		return st, err
	}

	// VACUUM reclaims the space freed above; it cannot run inside a transaction.
	if _, err := s.db.Exec(`VACUUM`); err != nil {
		return st, fmt.Errorf("vacuum: %w", err)
	}
	return st, nil
}
