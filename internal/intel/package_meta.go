package intel

import (
	"database/sql"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

type cachedPackageMeta struct {
	Context   *models.PackageContext
	FetchedAt time.Time
}

// GetPackageMeta returns cached npm package metadata when present.
func (s *Store) GetPackageMeta(name string) (cachedPackageMeta, bool, error) {
	var desc, license, homepage, popularity, fetchedAt sql.NullString
	var weekly sql.NullInt64
	err := s.db.QueryRow(`
SELECT description, license, homepage, weekly_downloads, popularity, fetched_at
FROM package_meta WHERE name=?`, name).Scan(&desc, &license, &homepage, &weekly, &popularity, &fetchedAt)
	if err == sql.ErrNoRows {
		return cachedPackageMeta{}, false, nil
	}
	if err != nil {
		return cachedPackageMeta{}, false, err
	}
	ctx := &models.PackageContext{
		Name:            name,
		Description:     desc.String,
		License:         license.String,
		Homepage:        homepage.String,
		WeeklyDownloads: weekly.Int64,
		Popularity:      models.PackagePopularity(popularity.String),
	}
	var at time.Time
	if fetchedAt.Valid {
		at, _ = time.Parse(time.RFC3339, fetchedAt.String)
	}
	return cachedPackageMeta{Context: ctx, FetchedAt: at.UTC()}, true, nil
}

// PutPackageMeta stores npm package metadata in the cache.
func (s *Store) PutPackageMeta(name string, ctx *models.PackageContext, at time.Time) error {
	if ctx == nil {
		return nil
	}
	_, err := s.db.Exec(`
INSERT INTO package_meta(name, description, license, homepage, weekly_downloads, popularity, fetched_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
  description=excluded.description,
  license=excluded.license,
  homepage=excluded.homepage,
  weekly_downloads=excluded.weekly_downloads,
  popularity=excluded.popularity,
  fetched_at=excluded.fetched_at`,
		name, ctx.Description, ctx.License, ctx.Homepage, ctx.WeeklyDownloads, string(ctx.Popularity), at.UTC().Format(time.RFC3339))
	return err
}
