package intel

import (
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// TestPruneToWeaponized keeps only advisories whose aliases carry an exploit
// signal or a high-enough EPSS score, and drops the rest along with the online
// caches.
func TestPruneToWeaponized(t *testing.T) {
	store := newTestStore(t)

	advs := []NPMAdvisory{
		{Package: "left-pad", ID: "GHSA-kev-1", Aliases: []string{"CVE-KEV-1"}},      // weaponized via KEV
		{Package: "right-pad", ID: "GHSA-epss-1", Aliases: []string{"CVE-EPSS-1"}},   // weaponized via EPSS >= 0.05
		{Package: "low-pad", ID: "GHSA-low-1", Aliases: []string{"CVE-LOWEPSS-1"}},   // EPSS below threshold -> dropped
		{Package: "quiet-pad", ID: "GHSA-quiet-1", Aliases: []string{"CVE-QUIET-1"}}, // no signal at all -> dropped
	}
	if _, err := store.UpsertOSVNPMAdvisories(advs); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	mustArtifact(t, store, models.RawArtifact{
		ID: "a-kev", CVEID: "CVE-KEV-1", Source: models.SourceKEV,
		TrustClass: models.TrustAuthoritative, Title: "KEV", ObservedAt: now,
	})
	mustArtifact(t, store, models.RawArtifact{
		ID: "a-epss-hi", CVEID: "CVE-EPSS-1", Source: models.SourceEPSS,
		TrustClass: models.TrustMedium, Title: "EPSS", ObservedAt: now,
		Metadata: map[string]string{"score": "0.42"},
	})
	mustArtifact(t, store, models.RawArtifact{
		ID: "a-epss-lo", CVEID: "CVE-LOWEPSS-1", Source: models.SourceEPSS,
		TrustClass: models.TrustMedium, Title: "EPSS", ObservedAt: now,
		Metadata: map[string]string{"score": "0.01"},
	})
	// Leave a row in an online cache to prove it gets cleared.
	if err := store.PutOSVCache("npm", "left-pad", "1.0.0", []models.CveMatch{{CVEID: "CVE-KEV-1"}}); err != nil {
		t.Fatal(err)
	}

	st, err := store.PruneToWeaponized(WeaponizedEPSSThreshold)
	if err != nil {
		t.Fatal(err)
	}
	if st.AdvisoriesKept != 2 {
		t.Errorf("AdvisoriesKept=%d, want 2 (KEV + high-EPSS)", st.AdvisoriesKept)
	}

	kept := func(alias string) bool { return len(store.OSVNPMPackagesForAlias(alias)) > 0 }
	if !kept("CVE-KEV-1") {
		t.Error("CVE-KEV-1 (KEV) dropped, want kept")
	}
	if !kept("CVE-EPSS-1") {
		t.Error("CVE-EPSS-1 (high EPSS) dropped, want kept")
	}
	if kept("CVE-LOWEPSS-1") {
		t.Error("CVE-LOWEPSS-1 (low EPSS) kept, want dropped")
	}
	if kept("CVE-QUIET-1") {
		t.Error("CVE-QUIET-1 (no signal) kept, want dropped")
	}

	// Online cache must be empty in a shipped snapshot.
	if _, ok := store.GetOSVMatches("npm", "left-pad", "1.0.0"); ok {
		t.Error("osv_cache not cleared by prune")
	}
}

func mustArtifact(t *testing.T, s *Store, a models.RawArtifact) {
	t.Helper()
	if err := s.UpsertArtifact(a); err != nil {
		t.Fatal(err)
	}
}
