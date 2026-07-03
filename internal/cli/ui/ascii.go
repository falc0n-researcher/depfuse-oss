package ui

import (
	_ "embed"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

//go:embed ascii_art.txt
var asciiArtRaw string

// PrintLogo writes the embedded ASCII art banner to w.
// Edit internal/cli/ui/ascii_art.txt to customize. Lines starting with # are ignored.
func PrintLogo(w io.Writer) {
	art := printableASCII(asciiArtRaw)
	if art == "" {
		return
	}
	for _, line := range strings.Split(art, "\n") {
		fmt.Fprintf(w, "  %s\n", styled(w, true, lipgloss.NewStyle().Bold(true).Foreground(colorAccent), line))
	}
}

// PrintHeader writes the logo and an optional subtitle (shown on every CLI command).
func PrintHeader(w io.Writer, subtitle string) {
	PrintLogo(w)
	if subtitle == "" {
		fmt.Fprintln(w)
		return
	}
	fmt.Fprintf(w, "  %s\n\n", Dim(w, subtitle))
}

// BeginCommand prints the logo banner at the start of a CLI command (use stderr).
func BeginCommand(w io.Writer, quiet bool, subtitle string) {
	if quiet {
		return
	}
	PrintHeader(w, subtitle)
}

// ShowBanner reports whether the ASCII banner should print for a scan-like command.
func ShowBanner(quiet bool, format string) bool {
	if quiet {
		return false
	}
	switch format {
	case "json", "sarif":
		return false
	default:
		return true
	}
}

func printableASCII(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			lines = append(lines, "")
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, strings.TrimRight(line, " \t"))
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}
