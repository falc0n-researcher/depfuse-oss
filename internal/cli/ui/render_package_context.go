package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/internal/pkgmeta"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// RenderPackageContextHeader prints npm ecosystem metadata for package lookups.
func RenderPackageContextHeader(w io.Writer, ctx *models.PackageContext) {
	renderPackageContextHeader(w, ctx)
}

func renderPackageContextHeader(w io.Writer, ctx *models.PackageContext) {
	if ctx == nil {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", Bold(w, "Package context"))
	if line := pkgmeta.SummaryLine(ctx); line != "" {
		fmt.Fprintf(w, "  %s\n", line)
	}
	if ctx.License != "" {
		fmt.Fprintf(w, "  %s\n", Dim(w, "License "+ctx.License))
	}
	if ctx.Homepage != "" {
		fmt.Fprintf(w, "  %s\n", Dim(w, ctx.Homepage))
	}
}

func renderPackageContextLine(w io.Writer, comp models.Component, ctx *models.PackageContext, indent string) {
	if ctx == nil {
		return
	}
	line := pkgmeta.ReceiptClaim(comp, ctx)
	if line == "" {
		return
	}
	fmt.Fprintf(w, "%s%s\n", indent, Dim(w, line))
}

func renderFindingPackageContext(w io.Writer, items []models.Finding) {
	for _, f := range items {
		if f.PackageContext == nil {
			continue
		}
		cve := strings.TrimSpace(f.CveMatch.CVEID)
		if cve == "" {
			cve = "finding"
		}
		fmt.Fprintf(w, "  %s\n", Bold(w, cve))
		renderPackageContextLine(w, f.Component, f.PackageContext, "    ")
	}
	if len(items) > 0 {
		fmt.Fprintln(w)
	}
}

func renderEcosystemContextSection(w io.Writer, findings []models.Finding) {
	seen := map[string]bool{}
	var rows [][]string
	for _, f := range findings {
		if f.PackageContext == nil || seen[f.Component.Name] {
			continue
		}
		seen[f.Component.Name] = true
		ctx := f.PackageContext
		downloads := pkgmeta.FormatWeeklyDownloads(ctx.WeeklyDownloads)
		if downloads == "" {
			downloads = "—"
		}
		pop := string(ctx.Popularity)
		if pop == "" {
			pop = "—"
		}
		desc := truncateOneLine(ctx.Description, 48)
		if desc == "" {
			desc = Dim(w, "—")
		}
		rows = append(rows, []string{
			f.Component.Name,
			downloads,
			pop,
			desc,
		})
	}
	if len(rows) == 0 {
		return
	}
	Section(w, "Ecosystem context", len(rows))
	Table{
		Headers: []string{"Package", "Downloads/week", "Tier", "Description"},
		Align:   repeatAlign(4, AlignLeft),
		MaxCol:  []int{20, 18, 14, 0},
		Rows:    rows,
	}.Print(w)
	fmt.Fprintln(w)
}
