package collector

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
)

const lodashAdvisory = `{
  "id": "GHSA-35jh-r3h4-6jhm",
  "summary": "Command Injection in lodash",
  "aliases": ["CVE-2021-23337"],
  "affected": [{
    "package": {"ecosystem":"npm","name":"lodash"},
    "ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]
  }]
}`

func TestRunOSVNPMPopulatesIndex(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("GHSA-35jh-r3h4-6jhm.json")
	_, _ = w.Write([]byte(lodashAdvisory))
	_ = zw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Write(buf.Bytes())
	}))
	defer srv.Close()

	prev := osvNPMExportURL
	SetOSVNPMExportURLForTest(srv.URL)
	defer SetOSVNPMExportURLForTest(prev)

	store, err := intel.Open(filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureFeeds(); err != nil {
		t.Fatal(err)
	}

	c := &Collector{Store: store}
	if err := c.runOSVNPM(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !store.HasOSVNPM() {
		t.Fatal("index empty after runOSVNPM")
	}
	m, ok := store.MatchNPM("lodash", "4.17.20")
	if !ok || len(m) != 1 {
		t.Fatalf("MatchNPM ok=%v n=%d want 1", ok, len(m))
	}
}
