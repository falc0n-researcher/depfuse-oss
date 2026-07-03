package report

import (
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func buildHTMLPage(result models.ScanResult) string {
	var b strings.Builder
	pages := buildDashboardData(result)

	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	b.WriteString("<title>Depfuse — Security Dashboard</title>")
	b.WriteString("<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">")
	b.WriteString("<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>")
	b.WriteString(`<link href="` + reportFontGoogleURL + `" rel="stylesheet">`)
	b.WriteString(htmlStyles)
	b.WriteString("</head><body>\n")

	writeDashboard(&b, result, pages)

	b.WriteString("</body></html>")
	return b.String()
}
