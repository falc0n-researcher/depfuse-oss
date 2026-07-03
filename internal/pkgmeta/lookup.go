package pkgmeta

import (
	"context"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const cacheTTL = 7 * 24 * time.Hour

// Lookup returns npm package context for names, using intel.db cache with network refresh.
func Lookup(ctx context.Context, store *intel.Store, offline bool, names ...string) (map[string]*models.PackageContext, error) {
	uniq := uniqueNames(names)
	out := make(map[string]*models.PackageContext, len(uniq))
	if len(uniq) == 0 {
		return out, nil
	}

	var needFetch []string
	for _, name := range uniq {
		if cached, ok, _ := store.GetPackageMeta(name); ok {
			fresh := !cached.FetchedAt.IsZero() && time.Since(cached.FetchedAt) <= cacheTTL
			useful := cached.Context != nil && (cached.Context.WeeklyDownloads > 0 || strings.TrimSpace(cached.Context.Description) != "")
			if fresh && useful {
				out[name] = cached.Context
				continue
			}
			if offline && cached.Context != nil {
				out[name] = cached.Context
				continue
			}
		}
		if offline {
			continue
		}
		needFetch = append(needFetch, name)
	}

	if len(needFetch) == 0 {
		return out, nil
	}

	downloads, err := FetchWeeklyDownloads(ctx, needFetch)
	if err != nil {
		downloads = map[string]int64{}
	}

	for _, name := range needFetch {
		desc, license, homepage, regErr := FetchRegistry(ctx, name)
		if regErr != nil {
			continue
		}
		weekly := downloads[name]
		ctxMeta := &models.PackageContext{
			Name:            name,
			Description:     desc,
			License:         license,
			Homepage:        homepage,
			WeeklyDownloads: weekly,
			Popularity:      PopularityFromWeeklyDownloads(weekly),
		}
		if weekly == 0 && strings.TrimSpace(desc) == "" {
			continue
		}
		out[name] = ctxMeta
		_ = store.PutPackageMeta(name, ctxMeta, time.Now().UTC())
	}
	return out, nil
}

func uniqueNames(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}
