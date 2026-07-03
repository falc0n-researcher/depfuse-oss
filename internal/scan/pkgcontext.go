package scan

import (
	"context"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/falc0n-researcher/depfuse-oss/internal/verdict"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func attachPackageContext(ctx context.Context, store *intel.Store, offline bool, findings []models.Finding, verbose bool, alwaysInclude ...string) map[string]models.PackageContext {
	names := packageNamesForContext(findings, verbose)
	names = append(names, alwaysInclude...)
	if len(names) == 0 {
		return nil
	}

	lookup, err := pkgmeta.Lookup(ctx, store, offline, names...)
	if err != nil || len(lookup) == 0 {
		return nil
	}

	out := make(map[string]models.PackageContext, len(lookup))
	for name, ctx := range lookup {
		if ctx != nil {
			out[name] = *ctx
		}
	}

	for i := range findings {
		ctx, ok := lookup[findings[i].Component.Name]
		if !ok || ctx == nil {
			continue
		}
		copyCtx := *ctx
		findings[i].PackageContext = &copyCtx
		if findings[i].Verdict.IsAction() {
			findings[i].Receipts = verdict.PrependEcosystemReceipt(findings[i].Receipts, findings[i].Component, ctx)
		}
	}
	return out
}

func packageNamesForContext(findings []models.Finding, verbose bool) []string {
	seen := map[string]bool{}
	var names []string
	for _, f := range findings {
		if f.Component.Name == "" || f.Component.Unresolved {
			continue
		}
		// Enrich action findings and direct dependencies for report ecosystem context.
		if !verbose && !f.Verdict.IsAction() && !f.Component.Direct {
			continue
		}
		if seen[f.Component.Name] {
			continue
		}
		seen[f.Component.Name] = true
		names = append(names, f.Component.Name)
	}
	return names
}

func primaryPackageContext(findings []models.Finding, packages map[string]models.PackageContext, name string) *models.PackageContext {
	if c, ok := packages[name]; ok {
		copy := c
		return &copy
	}
	for _, f := range findings {
		if f.PackageContext != nil && f.Component.Name == name {
			copy := *f.PackageContext
			return &copy
		}
	}
	return nil
}
