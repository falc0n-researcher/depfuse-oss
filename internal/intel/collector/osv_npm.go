package collector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
)

// osvNPMExportURL is the OSV bulk export for the npm ecosystem. Overridable for tests.
var osvNPMExportURL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"

// SetOSVNPMExportURLForTest overrides the OSV npm export endpoint (tests only).
func SetOSVNPMExportURLForTest(u string) { osvNPMExportURL = u }

// runOSVNPM downloads the OSV npm advisory export and rebuilds the offline match
// index. This is what makes `scan --offline` actually find vulnerabilities
// without a prior online scan.
func (c *Collector) runOSVNPM(ctx context.Context) error {
	var done func(string)
	if c.OnProgress != nil {
		done = c.OnProgress("OSV npm advisories")
	}
	finish := func(detail string) {
		if done != nil {
			done(detail)
		}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	runID := fmt.Sprintf("OSV_NPM-%d", time.Now().UnixNano())
	_ = c.Store.BeginFeedRun(runID, "OSV_NPM")

	data, err := downloadOSVNPM(fetchCtx, osvNPMExportURL)
	if err != nil {
		_ = c.Store.FinishFeedRun(runID, "failed", 0, 0, 0, "", err.Error())
		finish("failed")
		return fmt.Errorf("OSV_NPM: %w", err)
	}

	advs, err := intel.ParseOSVNPMZip(data)
	if err != nil {
		_ = c.Store.FinishFeedRun(runID, "failed", 0, 0, 0, "", err.Error())
		finish("failed")
		return fmt.Errorf("OSV_NPM parse: %w", err)
	}

	if err := c.Store.ResetOSVNPM(); err != nil {
		_ = c.Store.FinishFeedRun(runID, "failed", len(advs), 0, 200, "", err.Error())
		finish("failed")
		return fmt.Errorf("OSV_NPM reset: %w", err)
	}
	n, err := c.Store.UpsertOSVNPMAdvisories(advs)
	if err != nil {
		_ = c.Store.FinishFeedRun(runID, "failed", len(advs), n, 200, "", err.Error())
		finish("failed")
		return fmt.Errorf("OSV_NPM store: %w", err)
	}

	_ = c.Store.FinishFeedRun(runID, "success", len(advs), n, 200, "", "")
	finish(fmt.Sprintf("%d advisories", n))
	return nil
}

func downloadOSVNPM(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	// OSV npm export is tens of MB; cap generously to avoid unbounded memory.
	return io.ReadAll(io.LimitReader(resp.Body, 512<<20))
}
