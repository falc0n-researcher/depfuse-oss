package collector

import (
	"context"
	"fmt"
	"os"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel/snapshot"
)

// EnsureFresh runs collect when the database is missing or older than intel.CollectTTL().
// Skipped when DEPFUSE_SKIP_AUTO_COLLECT or DEPFUSE_OFFLINE is set.
func EnsureFresh(ctx context.Context, path string, quiet bool, onProgress ProgressFn) error {
	if intel.SkipAutoCollect() || intel.OfflineFromEnv() {
		return nil
	}

	needs, err := intel.NeedsRefresh(path, intel.CollectTTL())
	if err != nil {
		return err
	}
	if !needs {
		return nil
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		_, _ = snapshot.Extract(path)
	}

	if !quiet {
		ttl := intel.CollectTTL()
		fmt.Fprintf(os.Stderr, "Intelligence database is older than %s — refreshing feeds...\n", intel.FormatCollectTTL(ttl))
	}

	store, err := intel.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()

	col := New(store)
	col.OnProgress = onProgress
	if err := col.RunAll(ctx); err != nil {
		has, _ := store.HasData()
		if has {
			if !quiet {
				fmt.Fprintf(os.Stderr, "warning: collect finished with errors: %v\n", err)
			}
			return nil
		}
		return err
	}
	return nil
}
