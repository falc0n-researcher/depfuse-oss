package version

// Set at build time via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a human-readable version label.
func String() string {
	if Commit != "none" && len(Commit) >= 7 {
		return Version + " (" + Commit[:7] + ")"
	}
	return Version
}
