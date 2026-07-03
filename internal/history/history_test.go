package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func TestFindingKeyStable(t *testing.T) {
	comp := models.Component{Name: "next", Version: "15.1.0"}
	cve := models.CveMatch{CVEID: "CVE-2025-29927"}
	got := FindingKey(comp, cve)
	want := "next@15.1.0:CVE-2025-29927"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestToSnapshotRoundTrip(t *testing.T) {
	f := models.Finding{
		Component:      models.Component{Name: "lodash", Version: "4.17.20"},
		CveMatch:       models.CveMatch{CVEID: "CVE-2020-28500"},
		Classification: models.Classification{Priority: models.PriorityP4, Signals: models.Signals{EPSS: 0.02}},
		Verdict:        models.VerdictOK,
	}
	snap := ToSnapshot(f)
	if snap.Key != FindingKey(f.Component, f.CveMatch) {
		t.Fatalf("key mismatch")
	}
	if snap.Level != models.PriorityP4 {
		t.Fatalf("level %v", snap.Level)
	}
}

func TestSaveAndLoadPrevious(t *testing.T) {
	dir := t.TempDir()
	st, err := intel.Open(filepath.Join(dir, "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	hs := &Store{Intel: st}
	snaps := []models.HistorySnapshot{
		{Key: "a@1.0.0:CVE-1", CVEID: "CVE-1", Package: "a@1.0.0", Level: models.PriorityP4, Verdict: models.VerdictOK},
	}
	at := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if err := hs.Save("input-abc", "snap-v1", at, snaps); err != nil {
		t.Fatal(err)
	}
	prev, prevAt, err := hs.LoadPrevious("input-abc")
	if err != nil {
		t.Fatal(err)
	}
	if !prevAt.Equal(at) {
		t.Fatalf("time %v", prevAt)
	}
	if len(prev) != 1 || prev[0].Key != "a@1.0.0:CVE-1" {
		t.Fatalf("prev %+v", prev)
	}
}

func TestDeltaLevelUp(t *testing.T) {
	prev := []models.HistorySnapshot{
		{Key: "next@15.1.0:CVE-2025-29927", CVEID: "CVE-2025-29927", Package: "next@15.1.0",
			Level: models.PriorityP4, Verdict: models.VerdictOK, EPSS: 0.02},
	}
	curr := []models.Finding{{
		Component:      models.Component{Name: "next", Version: "15.1.0"},
		CveMatch:       models.CveMatch{CVEID: "CVE-2025-29927"},
		Classification: models.Classification{Priority: models.PriorityP0},
		Verdict:        models.VerdictFixNow,
	}}
	d := ComputeDelta(prev, curr, time.Now())
	if len(d.Escalated) != 1 || d.Escalated[0].Kind != models.DeltaLevelUp {
		t.Fatalf("escalated %+v", d.Escalated)
	}
}

func TestDeltaEPSSShift(t *testing.T) {
	prev := []models.HistorySnapshot{
		{Key: "lodash@4.17.20:CVE-2020-28500", CVEID: "CVE-2020-28500", Package: "lodash@4.17.20",
			Level: models.PriorityP3, Verdict: models.VerdictOK, EPSS: 0.12},
	}
	curr := []models.Finding{{
		Component:      models.Component{Name: "lodash", Version: "4.17.20"},
		CveMatch:       models.CveMatch{CVEID: "CVE-2020-28500"},
		Classification: models.Classification{Priority: models.PriorityP3, Signals: models.Signals{EPSS: 0.89}},
		Verdict:        models.VerdictOK,
	}}
	d := ComputeDelta(prev, curr, time.Now())
	if len(d.EPSSShifts) != 1 {
		t.Fatalf("epss shifts %+v", d.EPSSShifts)
	}
}

func TestPruneKeepsLatest(t *testing.T) {
	dir := t.TempDir()
	st, err := intel.Open(filepath.Join(dir, "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	hs := &Store{Intel: st}
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 12; i++ {
		snaps := []models.HistorySnapshot{
			{Key: "a@1.0.0:CVE-1", CVEID: "CVE-1", Package: "a@1.0.0", Level: models.PriorityP4, Verdict: models.VerdictOK},
		}
		if err := hs.Save("input-prune", "snap-v1", base.Add(time.Duration(i)*time.Hour), snaps); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM scan_history WHERE input_hash = ?`, "input-prune").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != maxHistoryPerInput {
		t.Fatalf("count %d want %d", count, maxHistoryPerInput)
	}
}
