package ui

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-runewidth"
	"golang.org/x/term"
)

const defaultTermWidth = 100

// IsTTY reports whether w is a terminal.
func IsTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// TermWidth returns the terminal width or a sensible default. When the output
// is not a TTY (piped or redirected), it honors the conventional COLUMNS
// environment variable so callers can widen captured output before falling back
// to the default.
func TermWidth(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if width, _, err := term.GetSize(int(f.Fd())); err == nil && width >= 40 {
			return width
		}
	}
	if c := envColumns(); c >= 40 {
		return c
	}
	return defaultTermWidth
}

// envColumns reads a positive COLUMNS override, or 0 when unset/invalid.
func envColumns() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS")))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// Color enabled when output is a TTY and DEPFUSE_NO_COLOR is unset.
func Color(w io.Writer) bool {
	if os.Getenv("DEPFUSE_NO_COLOR") != "" {
		return false
	}
	return IsTTY(w)
}

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
	orange = "\033[38;5;208m"
)

// Align controls cell alignment inside tables.
type Align int

const (
	AlignLeft Align = iota
	AlignRight
)

// Table renders a bordered ASCII table with correct Unicode column widths.
type Table struct {
	Headers []string
	Rows    [][]string
	Align   []Align
	// MaxCol caps display width for a column (0 = no cap).
	MaxCol []int
}

// TierStyle returns the styled exploit-risk level label.
func TierStyle(w io.Writer, tier string) string {
	return TierLipgloss(w, tier)
}

// VerdictStyle returns the styled action label.
func VerdictStyle(w io.Writer, verdict string) string {
	return VerdictLipgloss(w, verdict)
}

// MetaLine prints a labeled metadata row with aligned dots.
func MetaLine(w io.Writer, label, value string) {
	label = label + strings.Repeat(" ", max(0, 12-runewidth.StringWidth(label)))
	fmt.Fprintf(w, "  %s  %s\n", Label(w, label), value)
}

// Section prints a section heading with optional count badge.
func Section(w io.Writer, title string, count int) {
	fmt.Fprint(w, SectionHeading(w, title, count))
}

// ProgressBar renders a filled ratio bar.
func ProgressBar(width int, ratio float64, filled, empty string) string {
	if width < 4 {
		width = 4
	}
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	n := int(ratio * float64(width))
	if n > width {
		n = width
	}
	return "[" + strings.Repeat(filled, n) + strings.Repeat(empty, width-n) + "]"
}

// Progress tracks multi-step CLI operations on stderr.
type Progress struct {
	w     io.Writer
	quiet bool
	start time.Time
}

// NewProgress creates a progress reporter (typically stderr).
func NewProgress(w io.Writer, quiet bool) *Progress {
	return &Progress{w: w, quiet: quiet || !IsTTY(w)}
}

// Step announces a phase start; call the returned func when done.
func (p *Progress) Step(name string) func(detail string) {
	if p.quiet {
		return func(string) {}
	}
	if Color(p.w) {
		fmt.Fprintf(p.w, "  %s%s%s %s", dim, "○", reset, name)
	} else {
		fmt.Fprintf(p.w, "  · %s", name)
	}
	p.start = time.Now()
	return func(detail string) {
		elapsed := time.Since(p.start).Round(time.Millisecond)
		label := name
		if detail != "" {
			label = name + " — " + detail
		}
		bar := ProgressBar(16, 1, "█", "░")
		if Color(p.w) {
			fmt.Fprintf(p.w, "\r  %s%s%s %s %s%s%s %s\n",
				green, "●", reset, label, green, bar, reset, Dim(p.w, elapsed.String()))
		} else {
			fmt.Fprintf(p.w, "\r  * %s %s (%s)\n", label, bar, elapsed)
		}
	}
}

// Print writes the table to w, respecting terminal width.
func (t Table) Print(w io.Writer) {
	if len(t.Headers) == 0 {
		return
	}
	cols := len(t.Headers)
	widths := t.measureWidths(cols)
	widths = t.fitWidths(w, widths)

	indent := "  "
	fmt.Fprintln(w, indent+topRule(widths))
	t.printRow(w, indent, widths, t.Headers, true)
	fmt.Fprintln(w, indent+midRule(widths))
	for _, row := range t.Rows {
		t.printRow(w, indent, widths, row, false)
	}
	fmt.Fprintln(w, indent+botRule(widths))
}

func (t Table) measureWidths(cols int) []int {
	widths := make([]int, cols)
	for i, h := range t.Headers {
		widths[i] = displayWidth(h)
	}
	for _, row := range t.Rows {
		for i := 0; i < cols && i < len(row); i++ {
			if w := displayWidth(row[i]); w > widths[i] {
				widths[i] = w
			}
		}
	}
	for i, max := range t.MaxCol {
		if max > 0 && i < len(widths) && widths[i] > max {
			widths[i] = max
		}
	}
	return widths
}

func (t Table) fitWidths(w io.Writer, widths []int) []int {
	termW := TermWidth(w)
	// indent(2) + left border(1) + per col (width+2 padding + 1 border)
	total := 2 + 1
	for _, width := range widths {
		total += width + 3
	}
	// Repeatedly trim one unit off the widest shrinkable column until the table
	// fits or nothing can shrink further. Only capped columns (MaxCol>0) flex —
	// uncapped columns (tier, verdict, and reference URL columns) stay intact so
	// links are never truncated. Tables with no caps fall back to shrinking the
	// widest column, preserving the previous behaviour.
	const floor = 12
	hasCapped := false
	for i := range widths {
		if i < len(t.MaxCol) && t.MaxCol[i] > 0 {
			hasCapped = true
			break
		}
	}
	shrinkable := func(i int) bool {
		if widths[i] <= floor {
			return false
		}
		if !hasCapped {
			return true
		}
		return i < len(t.MaxCol) && t.MaxCol[i] > 0
	}
	for total > termW {
		shrinkIdx := -1
		for i := range widths {
			if !shrinkable(i) {
				continue
			}
			if shrinkIdx == -1 || widths[i] > widths[shrinkIdx] {
				shrinkIdx = i
			}
		}
		if shrinkIdx == -1 {
			break // nothing left to shrink
		}
		widths[shrinkIdx]--
		total--
	}
	return widths
}

func (t Table) printRow(w io.Writer, indent string, widths []int, cells []string, header bool) {
	var b strings.Builder
	b.WriteString(indent)
	b.WriteString("│")
	for i, width := range widths {
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		// Enforce the computed column width on any over-long cell so terminal
		// fitting (which may shrink even uncapped columns) never misaligns.
		if !header && displayWidth(cell) > width {
			cell = truncateCell(cell, width)
		}
		align := AlignLeft
		if i < len(t.Align) {
			align = t.Align[i]
		}
		if header && Color(w) {
			cell = styleTableHead.Render(stripANSI(cell))
		}
		b.WriteString(padCell(cell, width, align))
		b.WriteString("│")
	}
	fmt.Fprintln(w, b.String())
}

func padCell(cell string, width int, align Align) string {
	plain := stripANSI(cell)
	pad := width - runewidth.StringWidth(plain)
	if pad < 0 {
		pad = 0
	}
	spaces := strings.Repeat(" ", pad)
	if align == AlignRight {
		return " " + spaces + cell + " "
	}
	return " " + cell + spaces + " "
}

func truncateCell(cell string, width int) string {
	plain := stripANSI(cell)
	if runewidth.StringWidth(plain) <= width {
		return cell
	}
	if width <= 1 {
		return runewidth.Truncate(plain, width, "")
	}
	return runewidth.Truncate(plain, width-1, "…")
}

func displayWidth(s string) int {
	return runewidth.StringWidth(stripANSI(s))
}

func topRule(widths []int) string { return horizRule(widths, "┌", "┬", "┐") }
func midRule(widths []int) string { return horizRule(widths, "├", "┼", "┤") }
func botRule(widths []int) string { return horizRule(widths, "└", "┴", "┘") }

func horizRule(widths []int, left, mid, right string) string {
	var b strings.Builder
	b.WriteString(left)
	for i, width := range widths {
		if i > 0 {
			b.WriteString(mid)
		}
		b.WriteString(strings.Repeat("─", width+2))
	}
	b.WriteString(right)
	return b.String()
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for i := 0; i < len(s); i++ {
		if esc {
			if s[i] == 'm' {
				esc = false
			}
			continue
		}
		if s[i] == '\033' {
			esc = true
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
