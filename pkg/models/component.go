package models

// Scope indicates whether a dependency is production or development.
type Scope string

const (
	ScopeProd Scope = "prod"
	ScopeDev  Scope = "dev"
)

// Component is a resolved npm package at an exact lockfile version.
type Component struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	PURL         string   `json:"purl"`
	Scope        Scope    `json:"scope"`
	Direct       bool     `json:"direct"`
	Path         []string `json:"path,omitempty"`
	Manifest     string   `json:"manifest,omitempty"`
	LockfileRoot string   `json:"lockfileRoot,omitempty"` // relative path to lockfile dir from scan root
	Spec         string   `json:"spec,omitempty"`         // original manifest range spec (manifest-only scans)
	Unresolved   bool     `json:"unresolved,omitempty"`   // true when no concrete version could be pinned
}
