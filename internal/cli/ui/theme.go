package ui

import (
	"fmt"
	"io"

	"github.com/charmbracelet/lipgloss"
)

// Depfuse terminal palette (warm security-tool aesthetic).
var (
	colorAccent = lipgloss.Color("#FF6B2C")
	colorMuted  = lipgloss.Color("#6B7280")
	colorText   = lipgloss.Color("#E5E7EB")
	colorDanger = lipgloss.Color("#EF4444")
	colorWarn   = lipgloss.Color("#F59E0B")
	colorOK     = lipgloss.Color("#10B981")
	colorInfo   = lipgloss.Color("#38BDF8")
	colorPoC    = lipgloss.Color("#A78BFA")
)

var (
	styleTitle     = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleDim       = lipgloss.NewStyle().Foreground(colorMuted)
	styleBold      = lipgloss.NewStyle().Bold(true).Foreground(colorText)
	styleLabel     = lipgloss.NewStyle().Foreground(colorMuted)
	styleDanger    = lipgloss.NewStyle().Bold(true).Foreground(colorDanger)
	styleWarn      = lipgloss.NewStyle().Foreground(colorWarn)
	styleOK        = lipgloss.NewStyle().Foreground(colorOK)
	styleInfo      = lipgloss.NewStyle().Foreground(colorInfo)
	stylePoC       = lipgloss.NewStyle().Foreground(colorPoC)
	styleBadgeKEV  = lipgloss.NewStyle().Bold(true).Foreground(colorDanger)
	styleBadgeNuc  = lipgloss.NewStyle().Foreground(colorWarn)
	styleBadgeMSF  = lipgloss.NewStyle().Foreground(colorWarn)
	styleBadgeEDB  = lipgloss.NewStyle().Foreground(colorWarn)
	styleBadgePoC  = lipgloss.NewStyle().Foreground(colorPoC)
	styleTableHead = lipgloss.NewStyle().Bold(true).Foreground(colorText)
	styleSection   = lipgloss.NewStyle().Bold(true).Foreground(colorAccent).MarginTop(1)
	stylePanel     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#374151")).Padding(0, 1)
)

func styled(w io.Writer, enabled bool, s lipgloss.Style, text string) string {
	if !enabled || !Color(w) {
		return text
	}
	return s.Render(text)
}

// Title renders a section title.
func Title(w io.Writer, text string) string {
	return styled(w, true, styleTitle, text)
}

// Bold renders emphasized text.
func Bold(w io.Writer, text string) string {
	return styled(w, true, styleBold, text)
}

// Dim renders muted text.
func Dim(w io.Writer, text string) string {
	return styled(w, true, styleDim, text)
}

// Label renders a field label.
func Label(w io.Writer, text string) string {
	return styled(w, true, styleLabel, text)
}

// Danger renders critical emphasis.
func Danger(w io.Writer, text string) string {
	return styled(w, true, styleDanger, text)
}

// SectionHeading renders a report section header.
func SectionHeading(w io.Writer, title string, count int) string {
	line := title
	if count >= 0 {
		line = fmt.Sprintf("%s (%d)", title, count)
	}
	return "\n  " + styled(w, true, styleSection, line) + "\n"
}

// Panel wraps content in a subtle rounded border when color is enabled.
func Panel(w io.Writer, content string) string {
	if !Color(w) {
		return content
	}
	return "  " + stylePanel.Render(content)
}

// PriorityLipgloss returns styled priority code (P0–P4).
func PriorityLipgloss(w io.Writer, priority string) string {
	if !Color(w) {
		return priority
	}
	switch priority {
	case "P0":
		return styleDanger.Render(priority)
	case "P1":
		return lipgloss.NewStyle().Bold(true).Foreground(colorWarn).Render(priority)
	case "P2":
		return stylePoC.Render(priority)
	case "P3":
		return styleInfo.Render(priority)
	case "P4":
		return styleDim.Render(priority)
	default:
		return priority
	}
}

// TierLipgloss is an alias for PriorityLipgloss.
func TierLipgloss(w io.Writer, priority string) string {
	return PriorityLipgloss(w, priority)
}

// VerdictLipgloss returns styled verdict.
func VerdictLipgloss(w io.Writer, verdict string) string {
	if !Color(w) {
		return verdict
	}
	switch verdict {
	case "FIX NOW", "PATCH NOW":
		return styleDanger.Render(verdict)
	case "FIX SOON", "PATCH SOON":
		return styleWarn.Render(verdict)
	case "OK", "WATCH":
		return styleOK.Render(verdict)
	default:
		return verdict
	}
}

func badgeStyled(w io.Writer, label string, s lipgloss.Style) string {
	if !Color(w) {
		return label
	}
	return s.Render(label)
}
