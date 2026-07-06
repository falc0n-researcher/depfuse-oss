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

// Snapshot modes describe which OSV/intel index backed a scan.
const (
	SnapshotModeOnline           = "online"
	SnapshotModeFullOfflineDB    = "full-offline-db"
	SnapshotModeEmbeddedSnapshot = "embedded-snapshot"
)

// ComputeCoverage summarizes lockfile and transitive resolution completeness.
// peerDependencyCount is the number of packages present in the lockfile with
// no tracked parent in the dependency graph (optional/peer deps whose
// ancestry isn't recorded) — they are still scanned, but not shown in the
// dependency-path tree. snapshotMode records which OSV/intel index served
// this scan (see the SnapshotMode* constants).
func ComputeCoverage(root string, components []models.Component, tree TreeStats, peerDependencyCount int, snapshotMode string) *models.ScanCoverageMeta {
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
		Status:              CoverageComplete,
		HasLockfile:         hasLockfile,
		ManifestOnly:        !hasLockfile && UsesManifestOnlyResolution(components),
		UnresolvedCount:     len(unresolved),
		DirectCount:         direct,
		TransitiveCount:     tree.Transitive,
		TotalCount:          len(components),
		PeerDependencyCount: peerDependencyCount,
		SnapshotMode:        snapshotMode,
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
	case snapshotMode == SnapshotModeEmbeddedSnapshot:
		meta.Status = CoveragePartial
		meta.Message = "Lockfile resolution complete, but matched against the embedded weaponized-only index — quiet/non-tiering advisories are not covered until `depfuse collect` runs"
	default:
		meta.Message = "Lockfile resolution — full transitive dependency tree scanned"
	}
	return meta
}
