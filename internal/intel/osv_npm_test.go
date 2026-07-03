package intel

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

const lodashAdvisory = `{
  "id": "GHSA-35jh-r3h4-6jhm",
  "summary": "Command Injection in lodash",
  "aliases": ["CVE-2021-23337"],
  "published": "2021-02-15T00:00:00Z",
  "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H"}],
  "affected": [{
    "package": {"ecosystem":"npm","name":"lodash"},
    "ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]
  }],
  "references": [{"type":"WEB","url":"https://github.com/lodash/lodash"}]
}`

const nextAdvisory = `{
  "id": "GHSA-f82v-jwr5-mffw",
  "summary": "Authorization Bypass in Next.js Middleware",
  "aliases": ["CVE-2025-29927"],
  "affected": [{
    "package": {"ecosystem":"npm","name":"next"},
    "ranges": [{"type":"SEMVER","events":[{"introduced":"15.0.0"},{"fixed":"15.2.3"}]}]
  }]
}`

// non-npm entry must be ignored
const pypiAdvisory = `{
  "id": "PYSEC-2020-1",
  "affected": [{"package":{"ecosystem":"PyPI","name":"flask"},"ranges":[]}]
}`

// OSV malicious-package advisory — must be excluded from the triage index
const malwareAdvisory = `{
  "id": "MAL-2024-1234",
  "summary": "Malicious package",
  "affected": [{"package":{"ecosystem":"npm","name":"evil-typosquat"},"versions":["1.0.0"]}]
}`

func buildZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseAndMatchOSVNPM(t *testing.T) {
	zipData := buildZip(t, map[string]string{
		"GHSA-35jh-r3h4-6jhm.json": lodashAdvisory,
		"GHSA-f82v-jwr5-mffw.json": nextAdvisory,
		"PYSEC-2020-1.json":        pypiAdvisory,
		"MAL-2024-1234.json":       malwareAdvisory,
	})

	advs, err := ParseOSVNPMZip(zipData)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 2 { // pypi (non-npm) and MAL- (malware) excluded
		t.Fatalf("got %d npm advisories, want 2", len(advs))
	}

	store := newTestStore(t)
	n, err := store.UpsertOSVNPMAdvisories(advs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("upserted %d, want 2", n)
	}
	if !store.HasOSVNPM() {
		t.Fatal("HasOSVNPM=false after import")
	}

	// malware package must not be matchable (MAL- excluded at parse time)
	if mm, _ := store.MatchNPM("evil-typosquat", "1.0.0"); len(mm) != 0 {
		t.Errorf("malware package matched %d, want 0", len(mm))
	}

	// vulnerable version matches
	m, ok := store.MatchNPM("lodash", "4.17.20")
	if !ok || len(m) != 1 {
		t.Fatalf("lodash 4.17.20: ok=%v matches=%d want 1", ok, len(m))
	}
	if m[0].CVEID != "CVE-2021-23337" {
		t.Errorf("lodash CVE = %q want CVE-2021-23337", m[0].CVEID)
	}
	if len(m[0].FixedVersions) == 0 || m[0].FixedVersions[0] != "4.17.21" {
		t.Errorf("lodash fixed = %v want [4.17.21]", m[0].FixedVersions)
	}

	// patched version does NOT match
	if m, _ := store.MatchNPM("lodash", "4.17.21"); len(m) != 0 {
		t.Errorf("lodash 4.17.21 matched %d, want 0 (patched)", len(m))
	}

	// next outside range
	if m, _ := store.MatchNPM("next", "13.0.0"); len(m) != 0 {
		t.Errorf("next 13.0.0 matched %d, want 0 (below introduced)", len(m))
	}
	if m, _ := store.MatchNPM("next", "15.1.0"); len(m) != 1 {
		t.Errorf("next 15.1.0 matched %d, want 1", len(m))
	}

	// reverse alias lookup (cve mode offline)
	pkgs := store.OSVNPMPackagesForAlias("CVE-2025-29927")
	if len(pkgs) != 1 || pkgs[0].Name != "next" {
		t.Errorf("alias lookup = %v want [next]", pkgs)
	}
}

// TestHasOSVCacheIsIndependentOfNPMIndex guards the offline "matches will be
// empty" warning: the curated osv_cache is a valid offline match source on its
// own, so an empty osv_npm index must not imply no offline data (the demo DB
// ships exactly this way).
func TestHasOSVCacheIsIndependentOfNPMIndex(t *testing.T) {
	store := newTestStore(t)

	if store.HasOSVNPM() {
		t.Fatal("fresh store: HasOSVNPM=true, want false")
	}
	if store.HasOSVCache() {
		t.Fatal("fresh store: HasOSVCache=true, want false")
	}

	if err := store.PutOSVCache("npm", "lodash", "4.17.20", []models.CveMatch{{CVEID: "CVE-2021-23337"}}); err != nil {
		t.Fatal(err)
	}

	if store.HasOSVNPM() {
		t.Error("after osv_cache write: HasOSVNPM=true, want false (index still empty)")
	}
	if !store.HasOSVCache() {
		t.Error("after osv_cache write: HasOSVCache=false, want true")
	}
}
