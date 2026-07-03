package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const treeCacheTTL = 7 * 24 * time.Hour

type treeCacheEntry struct {
	SavedAt    time.Time          `json:"savedAt"`
	Components []models.Component `json:"components"`
}

func treeCacheDir() string {
	if v := strings.TrimSpace(os.Getenv("DEPFUSE_TREE_CACHE")); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".depfuse", "deptree")
}

func treeCacheKey(roots []models.Component, opts TreeOptions) string {
	var parts []string
	for _, r := range roots {
		parts = append(parts, fmt.Sprintf("%s@%s", r.Name, r.Version))
	}
	sort.Strings(parts)
	raw := fmt.Sprintf("roots=%s|depth=%d|dev=%v", strings.Join(parts, ","), opts.Depth, opts.IncludeDev)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

func loadTreeCache(key string) ([]models.Component, bool, error) {
	path := filepath.Join(treeCacheDir(), key+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var entry treeCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false, err
	}
	if time.Since(entry.SavedAt) > treeCacheTTL {
		return nil, false, nil
	}
	return entry.Components, true, nil
}

func saveTreeCache(key string, comps []models.Component) error {
	dir := treeCacheDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entry := treeCacheEntry{SavedAt: time.Now().UTC(), Components: comps}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, key+".json"), data, 0o644)
}
