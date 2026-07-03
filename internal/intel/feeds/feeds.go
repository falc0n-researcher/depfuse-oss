package feeds

import (
	"context"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
)

// Feed fetches and normalizes intelligence from an external source.
type Feed interface {
	Name() string
	Fetch(ctx context.Context, runID string) ([]intel.NormalizedRecord, error)
}

// All returns the default enabled feeds (exploit-risk-first, EPSS last).
func All(cacheDir string) []Feed {
	return []Feed{
		&KEV{},
		&Metasploit{},
		&ExploitDB{},
		&Nuclei{CacheDir: cacheDir},
		&PoCGitHub{},
		&EPSS{},
	}
}
