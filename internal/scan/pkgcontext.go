package scan

import (
	"context"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/falc0n-researcher/depfuse-oss/internal/verdict"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func attachPackageContext(ctx context.Context, store *intel.Store, offline bool, findings []models.Finding, components []models.Component, alwaysInclude ...string) map[string]models.PackageContext {
	names := packageNamesForContext(findings, components)
	names = append(names, alwaysInclude...)
	if len(names) == 0 {
		return nil
	}

	lookup, err := pkgmeta.Lookup(ctx, store, offline, names...)
	if err != nil {
		return nil
	}
	if len(lookup) == 0 {
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

func packageNamesForContext(findings []models.Finding, components []models.Component) []string {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	for _, f := range findings {
		if f.Component.Unresolved {
			continue
		}
		add(f.Component.Name)
	}
	for _, c := range components {
		add(c.Name)
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
