package resolve

import (
	"fmt"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const (
	CoverageComplete   = "complete"
	CoveragePartial    = "partial"
	CoverageIncomplete = "incomplete"
)

// ComputeCoverage summarizes lockfile and transitive resolution completeness.
func ComputeCoverage(root string, components []models.Component, tree TreeStats) *models.ScanCoverageMeta {
	if root == "" {
		return nil
	}
	_, lockPath := FindLockfile(root, root)
	hasLockfile := lockPath != ""
	unresolved := UnresolvedComponents(components)

	direct := 0
	for _, c := range components {
		if c.Direct {
			direct++
		}
	}

	meta := &models.ScanCoverageMeta{
		Status:          CoverageComplete,
		HasLockfile:     hasLockfile,
		ManifestOnly:    !hasLockfile && UsesManifestOnlyResolution(components),
		UnresolvedCount: len(unresolved),
		DirectCount:     direct,
		TransitiveCount: tree.Transitive,
		TotalCount:      len(components),
	}

	switch {
	case len(unresolved) > 0:
		meta.Status = CoverageIncomplete
		meta.Message = fmt.Sprintf("SCAN INCOMPLETE — %d/%d dependencies could not be pinned and were not scanned",
			len(unresolved), len(components))
	case !hasLockfile && tree.Transitive == 0:
		meta.Status = CoverageIncomplete
		meta.Message = "SCAN INCOMPLETE — no lockfile; only direct dependencies scanned, transitive deps not covered"
	case !hasLockfile && tree.Transitive > 0:
		meta.Status = CoveragePartial
		meta.Message = fmt.Sprintf("Partial coverage — no lockfile; %d transitive packages resolved via registry tree (not lockfile-pinned)",
			tree.Transitive)
	default:
		meta.Message = "Lockfile resolution — full transitive dependency tree scanned"
	}
	return meta
}
