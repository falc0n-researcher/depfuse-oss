package intel

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultCollectTTL = 4 * time.Hour

// ResolvedPath returns the intelligence database path (~/.depfuse/intel.db).
// Override with DEPFUSE_INTEL_DB for tests and CI fixtures.
func ResolvedPath() string {
	if v := strings.TrimSpace(os.Getenv("DEPFUSE_INTEL_DB")); v != "" {
		return v
	}
	return DefaultPath()
}

// OfflineFromEnv reports whether network calls are disabled (DEPFUSE_OFFLINE=1).
func OfflineFromEnv() bool {
	v := strings.TrimSpace(os.Getenv("DEPFUSE_OFFLINE"))
	return v == "1" || strings.EqualFold(v, "true")
}

// SkipAutoCollect reports whether automatic refresh is disabled (DEPFUSE_SKIP_AUTO_COLLECT=1).
func SkipAutoCollect() bool {
	v := strings.TrimSpace(os.Getenv("DEPFUSE_SKIP_AUTO_COLLECT"))
	return v == "1" || strings.EqualFold(v, "true")
}

// CollectTTL returns how long a collect remains valid before auto-refresh (default 4h).
func CollectTTL() time.Duration {
	if v := os.Getenv("DEPFUSE_COLLECT_TTL"); v != "" {
		if h, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && h > 0 {
			return time.Duration(h) * time.Hour
		}
	}
	return defaultCollectTTL
}

// NeedsRefresh reports whether path is missing, empty, or older than ttl.
func NeedsRefresh(path string, ttl time.Duration) (bool, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return true, nil
	} else if err != nil {
		return false, err
	}

	store, err := Open(path)
	if err != nil {
		return true, err
	}
	defer store.Close()

	has, err := store.HasData()
	if err != nil {
		return true, err
	}
	if !has {
		return true, nil
	}

	at, err := store.CollectedAt()
	if err != nil || at.IsZero() {
		return true, nil
	}
	return time.Since(at) > ttl, nil
}

// FormatCollectTTL renders a duration for user-facing refresh messages.
func FormatCollectTTL(d time.Duration) string {
	if d%(time.Hour) == 0 {
		h := int(d / time.Hour)
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	return d.Truncate(time.Minute).String()
}
