package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel/feeds"
)

// ProgressFn reports long-running phases; the returned func completes the phase.
type ProgressFn func(phase string) func(detail string)

// Collector orchestrates intelligence feed ingestion.
type Collector struct {
	Store      *intel.Store
	CacheDir   string
	FeedList   []feeds.Feed
	OnProgress ProgressFn
}

var feedTimeouts = map[string]time.Duration{
	"KEV":        10 * time.Minute,
	"METASPLOIT": 3 * time.Minute,
	"EXPLOITDB":  5 * time.Minute,
	"NUCLEI":     15 * time.Minute,
	"POC_GITHUB": 10 * time.Minute,
	"EPSS":       15 * time.Minute,
}

// New creates a collector with default feeds.
func New(store *intel.Store) *Collector {
	cacheDir := intel.CacheDir()
	if v := os.Getenv("DEPFUSE_CACHE_DIR"); v != "" {
		cacheDir = v
	}
	return &Collector{
		Store:    store,
		CacheDir: cacheDir,
		FeedList: feeds.All(cacheDir),
	}
}

// RunAll fetches exploit-risk feeds, enriches advisories from OSV, then stores EPSS.
func (c *Collector) RunAll(ctx context.Context) error {
	if _, err := c.Store.AbortRunningFeedRuns("aborted: new collect started"); err != nil {
		return err
	}
	if err := c.Store.EnsureFeeds(); err != nil {
		return err
	}

	var firstErr error
	var epss, poc feeds.Feed

	for _, feed := range c.FeedList {
		switch feed.Name() {
		case "EPSS":
			epss = feed
		case "POC_GITHUB":
			poc = feed
		default:
			if err := c.runFeed(ctx, feed); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	if poc != nil {
		if err := c.runPoCGitHubFeed(ctx, poc); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if err := c.runEnrich(ctx); err != nil && firstErr == nil {
		firstErr = err
	}

	// Build the offline npm match index so `scan --offline` finds advisories
	// without a prior online scan. Non-fatal: a stale or missing index degrades
	// to "no offline matches" rather than failing the whole collect.
	if err := c.runOSVNPM(ctx); err != nil && firstErr == nil {
		firstErr = err
	}

	if epss != nil {
		if err := c.runFeed(ctx, epss); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if err := c.Store.SetCollectedMeta(); err != nil && firstErr == nil {
		firstErr = err
	}

	ok, _ := c.Store.HasData()
	if !ok && firstErr == nil {
		firstErr = fmt.Errorf("collect produced no artifacts")
	}
	return firstErr
}

func (c *Collector) runEnrich(ctx context.Context) error {
	var done func(string)
	if c.OnProgress != nil {
		done = c.OnProgress("Enrich advisories")
	}
	enrichCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	n, err := intel.EnrichVulnRecords(enrichCtx, c.Store)
	if done != nil {
		if err != nil {
			done("failed")
		} else {
			done(fmt.Sprintf("%d CVEs", n))
		}
	}
	return err
}

func (c *Collector) runPoCGitHubFeed(ctx context.Context, feed feeds.Feed) error {
	pg, ok := feed.(*feeds.PoCGitHub)
	if !ok {
		return c.runFeed(ctx, feed)
	}
	cves, err := c.Store.WeaponizationCVEs()
	if err != nil {
		return err
	}
	if len(cves) == 0 {
		return nil
	}
	pg.CVEs = cves
	return c.runFeed(ctx, pg)
}

func (c *Collector) runFeed(ctx context.Context, feed feeds.Feed) error {
	var done func(string)
	if c.OnProgress != nil {
		done = c.OnProgress("Collect " + feed.Name())
	}
	finish := func(detail string) {
		if done != nil {
			done(detail)
		}
	}

	timeout := feedTimeouts[feed.Name()]
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	feedCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if feed.Name() == "EPSS" {
		if prev, err := c.Store.LastFeedContentSHA("EPSS"); err == nil && prev != "" {
			feedCtx = feeds.WithEPSSPreviousHash(feedCtx, prev)
		}
	}

	runID := fmt.Sprintf("%s-%d", feed.Name(), time.Now().UnixNano())
	if err := c.Store.BeginFeedRun(runID, feed.Name()); err != nil {
		return err
	}

	records, err := feed.Fetch(feedCtx, runID)
	status := "success"
	errMsg := ""
	upserted := 0
	contentSHA := contentHash(records)
	if epss, ok := feed.(*feeds.EPSS); ok && epss.LastBodySHA() != "" {
		contentSHA = epss.LastBodySHA()
	}

	if err != nil {
		if feeds.IsUnchanged(err) {
			if prev, _ := c.Store.LastFeedContentSHA(feed.Name()); prev != "" {
				contentSHA = prev
			}
			_ = c.Store.FinishFeedRun(runID, "success", 0, 0, 200, contentSHA, "unchanged")
			finish("skipped (unchanged)")
			return nil
		}
		status = "failed"
		errMsg = err.Error()
		_ = c.Store.FinishFeedRun(runID, status, 0, 0, 0, "", errMsg)
		finish("failed")
		return err
	}

	upserted, err = c.Store.UpsertNormalizedRecords(records)
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	} else if upserted != len(records) {
		status = "partial"
		errMsg = fmt.Sprintf("upserted %d of %d", upserted, len(records))
	}

	_ = c.Store.FinishFeedRun(runID, status, len(records), upserted, 200, contentSHA, errMsg)
	if status == "failed" {
		finish("failed")
		return fmt.Errorf("%s: %s", feed.Name(), errMsg)
	}
	finish(fmt.Sprintf("%d artifacts", upserted))
	return nil
}

func extractSHA(msg string) string {
	start := strings.LastIndex(msg, "(")
	end := strings.LastIndex(msg, ")")
	if start >= 0 && end > start {
		return msg[start+1 : end]
	}
	return ""
}

func contentHash(records []intel.NormalizedRecord) string {
	h := sha256.New()
	for _, r := range records {
		_, _ = h.Write([]byte(r.CanonicalID))
		_, _ = h.Write([]byte(r.Artifact.ID))
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}
