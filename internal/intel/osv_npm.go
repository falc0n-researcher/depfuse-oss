package intel

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/semver"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// NPMAdvisory is a single OSV npm advisory entry for one affected package,
// stored in compact form for offline version-range matching.
type NPMAdvisory struct {
	Package    string        `json:"pkg"`
	ID         string        `json:"id"`
	Aliases    []string      `json:"aliases,omitempty"`
	Summary    string        `json:"summary,omitempty"`
	Severity   string        `json:"severity,omitempty"`
	Published  string        `json:"published,omitempty"`
	References []string      `json:"refs,omitempty"`
	Ranges     []NPMInterval `json:"ranges,omitempty"`
	Versions   []string      `json:"versions,omitempty"`
}

// NPMInterval is a half-open affected interval [Introduced, Fixed).
type NPMInterval struct {
	Introduced string `json:"i,omitempty"`
	Fixed      string `json:"f,omitempty"`
}

// --- OSV export parsing ---

type osvExportRecord struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Severity  []struct {
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Withdrawn string `json:"withdrawn"`
}

// ParseOSVNPMZip parses an OSV ecosystem export (all.zip) into per-package
// advisory records. Each affected npm package in each advisory yields one row.
func ParseOSVNPMZip(data []byte) ([]NPMAdvisory, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var out []NPMAdvisory
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		var rec osvExportRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue // skip malformed entries rather than aborting the whole import
		}
		out = append(out, advisoriesFromRecord(rec)...)
	}
	return out, nil
}

func advisoriesFromRecord(rec osvExportRecord) []NPMAdvisory {
	if rec.ID == "" || rec.Withdrawn != "" {
		return nil
	}
	// Skip OSV malicious-package (malware/typosquat) advisories. They are the
	// bulk of the npm export, carry no exploit signal (always Watch/Quiet), and
	// belong to supply-chain malware detection, not exploit-risk-ranked CVE
	// triage. Excluding them keeps the offline index small and noise-free.
	if isMalwareAdvisory(rec.ID, rec.Aliases) {
		return nil
	}
	severity := ""
	if len(rec.Severity) > 0 {
		severity = rec.Severity[0].Score
	}
	var refs []string
	for _, r := range rec.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}
	var out []NPMAdvisory
	for _, aff := range rec.Affected {
		if !strings.EqualFold(aff.Package.Ecosystem, "npm") || aff.Package.Name == "" {
			continue
		}
		var intervals []NPMInterval
		for _, rng := range aff.Ranges {
			if strings.EqualFold(rng.Type, "GIT") {
				continue
			}
			cur := NPMInterval{}
			open := false
			for _, ev := range rng.Events {
				if ev.Introduced != "" {
					cur = NPMInterval{Introduced: ev.Introduced}
					open = true
				}
				if ev.Fixed != "" {
					cur.Fixed = ev.Fixed
					intervals = append(intervals, cur)
					open = false
				}
			}
			if open {
				intervals = append(intervals, cur)
			}
		}
		// Ranges are authoritative and compact; the enumerated versions list can
		// be huge, so only retain it when there are no ranges to match against.
		versions := aff.Versions
		if len(intervals) > 0 {
			versions = nil
		}
		out = append(out, NPMAdvisory{
			Package:    aff.Package.Name,
			ID:         rec.ID,
			Aliases:    rec.Aliases,
			Summary:    rec.Summary,
			Severity:   severity,
			Published:  rec.Published,
			References: refs,
			Ranges:     intervals,
			Versions:   versions,
		})
	}
	return out
}

// isMalwareAdvisory reports whether an advisory is an OSV malicious-package
// record (id or any alias prefixed "MAL-").
func isMalwareAdvisory(id string, aliases []string) bool {
	if strings.HasPrefix(id, "MAL-") {
		return true
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "MAL-") {
			return true
		}
	}
	return false
}

// --- Store: write ---

// UpsertOSVNPMAdvisories writes advisories into the offline match index in a
// single transaction and returns the row count written.
func (s *Store) UpsertOSVNPMAdvisories(advs []NPMAdvisory) (int, error) {
	if len(advs) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	insAdv, err := tx.Prepare(`INSERT INTO osv_npm(package, advisory_id, payload) VALUES(?,?,?)
ON CONFLICT(package, advisory_id) DO UPDATE SET payload=excluded.payload`)
	if err != nil {
		return 0, err
	}
	defer insAdv.Close()
	insAlias, err := tx.Prepare(`INSERT OR IGNORE INTO osv_npm_alias(alias, package, advisory_id) VALUES(?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer insAlias.Close()

	n := 0
	for _, a := range advs {
		payload, err := json.Marshal(a)
		if err != nil {
			continue
		}
		if _, err := insAdv.Exec(a.Package, a.ID, string(payload)); err != nil {
			return n, err
		}
		n++
		ids := append([]string{a.ID}, a.Aliases...)
		for _, id := range ids {
			if id != "" {
				_, _ = insAlias.Exec(id, a.Package, a.ID)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return n, err
	}
	return n, nil
}

// ResetOSVNPM clears the offline advisory index (called before a fresh import).
func (s *Store) ResetOSVNPM() error {
	if _, err := s.db.Exec(`DELETE FROM osv_npm`); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM osv_npm_alias`)
	return err
}

// --- Store: read / match ---

// HasOSVNPM reports whether the offline npm advisory index is populated.
func (s *Store) HasOSVNPM() bool {
	var n int
	if err := s.db.QueryRow(`SELECT 1 FROM osv_npm LIMIT 1`).Scan(&n); err != nil {
		return false
	}
	return true
}

// HasOSVCache reports whether the curated OSV match cache holds any rows. It is
// the other offline match source besides the osv_npm range index, so an empty
// osv_npm index does not mean offline matching is impossible.
func (s *Store) HasOSVCache() bool {
	var n int
	if err := s.db.QueryRow(`SELECT 1 FROM osv_cache LIMIT 1`).Scan(&n); err != nil {
		return false
	}
	return true
}

// MatchNPM returns OSV advisories affecting name@version from the offline index.
// The bool is true when the index was consulted (so an empty result is an
// authoritative "no advisories", not "unknown").
func (s *Store) MatchNPM(name, version string) ([]models.CveMatch, bool) {
	if !s.HasOSVNPM() {
		return nil, false
	}
	rows, err := s.db.Query(`SELECT payload FROM osv_npm WHERE package=?`, name)
	if err != nil {
		return nil, true
	}
	defer rows.Close()

	seen := map[string]bool{}
	var out []models.CveMatch
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			continue
		}
		var adv NPMAdvisory
		if err := json.Unmarshal([]byte(payload), &adv); err != nil {
			continue
		}
		if !adv.affects(version) {
			continue
		}
		m := adv.toCveMatch()
		key := m.CVEID
		if key == "" {
			key = m.OSVID
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AdvisoryID() < out[j].AdvisoryID() })
	return out, true
}

// OSVNPMPackagesForAlias returns npm package names affected by an advisory id
// (CVE/GHSA/OSV), with a representative fixed version, for offline cve lookups.
func (s *Store) OSVNPMPackagesForAlias(ids ...string) []models.AffectedPackage {
	seen := map[string]bool{}
	var out []models.AffectedPackage
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		rows, err := s.db.Query(`
SELECT n.payload FROM osv_npm_alias a
JOIN osv_npm n ON n.package = a.package AND n.advisory_id = a.advisory_id
WHERE a.alias = ?`, id)
		if err != nil {
			continue
		}
		for rows.Next() {
			var payload string
			if err := rows.Scan(&payload); err != nil {
				continue
			}
			var adv NPMAdvisory
			if err := json.Unmarshal([]byte(payload), &adv); err != nil {
				continue
			}
			if seen[adv.Package] {
				continue
			}
			seen[adv.Package] = true
			out = append(out, models.AffectedPackage{
				Name:         adv.Package,
				Ecosystem:    "npm",
				FixedVersion: adv.firstFixed(),
			})
		}
		rows.Close()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// --- advisory evaluation ---

func (a NPMAdvisory) affects(version string) bool {
	if _, ok := semver.Parse(version); !ok {
		return false
	}
	for _, v := range a.Versions {
		if v == version || semver.CompareStr(v, version) == 0 {
			return true
		}
	}
	for _, iv := range a.Ranges {
		lo := iv.Introduced
		if lo == "" || lo == "0" {
			lo = "0.0.0"
		}
		if semver.CompareStr(version, lo) < 0 {
			continue
		}
		if iv.Fixed != "" && semver.CompareStr(version, iv.Fixed) >= 0 {
			continue
		}
		return true
	}
	return false
}

func (a NPMAdvisory) firstFixed() string {
	for _, iv := range a.Ranges {
		if iv.Fixed != "" {
			return iv.Fixed
		}
	}
	return ""
}

func (a NPMAdvisory) toCveMatch() models.CveMatch {
	cve := ""
	if cvePattern.MatchString(a.ID) {
		cve = a.ID
	} else {
		for _, al := range a.Aliases {
			if cvePattern.MatchString(al) {
				cve = al
				break
			}
		}
	}
	ghsa := ""
	if strings.HasPrefix(a.ID, "GHSA-") {
		ghsa = a.ID
	} else {
		for _, al := range a.Aliases {
			if strings.HasPrefix(al, "GHSA-") {
				ghsa = al
				break
			}
		}
	}
	var fixed []string
	for _, iv := range a.Ranges {
		if iv.Fixed != "" {
			fixed = append(fixed, iv.Fixed)
		}
	}
	var published time.Time
	if a.Published != "" {
		published, _ = time.Parse(time.RFC3339, a.Published)
	}
	id := cve
	if id == "" {
		id = a.ID
	}
	return models.CveMatch{
		CVEID:         id,
		OSVID:         a.ID,
		GHSAID:        ghsa,
		Aliases:       a.Aliases,
		Summary:       a.Summary,
		Severity:      a.Severity,
		Published:     published,
		FixedVersions: fixed,
		References:    a.References,
		AffectedPackages: []models.AffectedPackage{
			{Name: a.Package, Ecosystem: "npm", FixedVersion: firstNonEmptyStr(fixed)},
		},
	}
}

func firstNonEmptyStr(vals []string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
