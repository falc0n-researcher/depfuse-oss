package models

// PackagePopularity labels npm weekly download volume.
type PackagePopularity string

const (
	PopularityUbiquitous PackagePopularity = "ubiquitous"
	PopularityWidelyUsed PackagePopularity = "widely-used"
	PopularityPopular    PackagePopularity = "popular"
	PopularityModerate   PackagePopularity = "moderate"
	PopularityNiche      PackagePopularity = "niche"
)

// PackageContext is npm registry metadata used for ecosystem exposure context.
type PackageContext struct {
	Name            string            `json:"name"`
	Description     string            `json:"description,omitempty"`
	WeeklyDownloads int64             `json:"weeklyDownloads,omitempty"`
	License         string            `json:"license,omitempty"`
	Homepage        string            `json:"homepage,omitempty"`
	Popularity      PackagePopularity `json:"popularity,omitempty"`
	// LifecycleScripts lists npm install-time hooks (preinstall, install,
	// postinstall, prepare) present on the package's latest published
	// version. This is supply-chain context, not exploit evidence — it never
	// affects Priority or Verdict.
	LifecycleScripts []string `json:"lifecycleScripts,omitempty"`
}
