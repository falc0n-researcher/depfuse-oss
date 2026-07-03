package verdict

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// BuildReceipts assembles deterministic verdict receipt bullets from
// classification evidence and dependency exposure metadata.
func BuildReceipts(comp models.Component, cve models.CveMatch, class models.Classification) []models.VerdictReceipt {
	var out []models.VerdictReceipt
	seen := map[models.ReceiptKind]bool{}

	for _, e := range class.Evidence {
		kind := receiptKindForSource(e.Source)
		if kind == "" || seen[kind] {
			continue
		}
		seen[kind] = true
		out = append(out, models.VerdictReceipt{
			Kind:  kind,
			Claim: e.Claim,
			URL:   e.URL,
		})
	}

	if class.Signals.EPSS > 0 && !seen[models.ReceiptEPSS] {
		out = append(out, models.VerdictReceipt{
			Kind:  models.ReceiptEPSS,
			Claim: fmt.Sprintf("EPSS score %.2f (elevated 30-day exploitation likelihood)", class.Signals.EPSS),
		})
	}

	out = append(out, exposureReceipt(comp))
	return sortReceipts(out)
}

// PrependEcosystemReceipt adds npm ecosystem context before the lockfile exposure line.
func PrependEcosystemReceipt(recs []models.VerdictReceipt, comp models.Component, ctx *models.PackageContext) []models.VerdictReceipt {
	claim := pkgmeta.ReceiptClaim(comp, ctx)
	if claim == "" {
		return recs
	}
	eco := models.VerdictReceipt{Kind: models.ReceiptEcosystem, Claim: claim}
	if ctx != nil && ctx.Homepage != "" {
		eco.URL = ctx.Homepage
	}
	out := make([]models.VerdictReceipt, 0, len(recs)+1)
	out = append(out, eco)
	for _, r := range recs {
		if r.Kind != models.ReceiptEcosystem {
			out = append(out, r)
		}
	}
	return sortReceipts(out)
}

func receiptKindForSource(src models.Source) models.ReceiptKind {
	switch src {
	case models.SourceKEV:
		return models.ReceiptKEV
	case models.SourceNuclei:
		return models.ReceiptNuclei
	case models.SourceMetasploit:
		return models.ReceiptMSF
	case models.SourceExploitDB:
		return models.ReceiptEDB
	case models.SourcePoCGitHub, models.SourceVulnCheckXDB:
		return models.ReceiptPoC
	default:
		return ""
	}
}

func exposureReceipt(comp models.Component) models.VerdictReceipt {
	if len(comp.Path) > 1 {
		return models.VerdictReceipt{
			Kind:  models.ReceiptDependencyPath,
			Claim: fmt.Sprintf("Transitive via %s", dependencyPathClaim(comp)),
		}
	}
	claim := fmt.Sprintf("Lockfile confirms %s@%s", comp.Name, comp.Version)
	if comp.Manifest != "" && comp.LockfileRoot == "" {
		claim = fmt.Sprintf("Manifest confirms %s@%s", comp.Name, comp.Version)
	}
	if comp.LockfileRoot != "" {
		claim = fmt.Sprintf("%s in %s", claim, strings.TrimPrefix(comp.LockfileRoot, "./"))
	}
	return models.VerdictReceipt{
		Kind:  models.ReceiptExposure,
		Claim: claim,
	}
}

func dependencyPathClaim(comp models.Component) string {
	parts := make([]string, len(comp.Path))
	for i, name := range comp.Path {
		if i == len(comp.Path)-1 {
			parts[i] = name + "@" + comp.Version
		} else {
			parts[i] = name
		}
	}
	return strings.Join(parts, " → ")
}

func sortReceipts(in []models.VerdictReceipt) []models.VerdictReceipt {
	order := []models.ReceiptKind{
		models.ReceiptKEV,
		models.ReceiptNuclei,
		models.ReceiptMSF,
		models.ReceiptEDB,
		models.ReceiptPoC,
		models.ReceiptEPSS,
		models.ReceiptEcosystem,
		models.ReceiptDependencyPath,
		models.ReceiptExposure,
	}
	byKind := make(map[models.ReceiptKind]models.VerdictReceipt, len(in))
	for _, r := range in {
		byKind[r.Kind] = r
	}
	out := make([]models.VerdictReceipt, 0, len(in))
	for _, k := range order {
		if r, ok := byKind[k]; ok {
			out = append(out, r)
		}
	}
	return out
}
