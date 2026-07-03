package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTableUnicodeAlignment(t *testing.T) {
	var buf bytes.Buffer
	Table{
		Headers: []string{"Metric", "Count"},
		Rows: [][]string{
			{"T2–T4 noise", "20"},
			{"GHSA-f82v → CVE-2025-29927", "3"},
		},
	}.Print(&buf)

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 4)
	for _, line := range lines {
		if strings.Contains(line, "│") {
			require.True(t, strings.HasPrefix(line, "  │"), "row should align: %q", line)
		}
	}
	require.Contains(t, out, "T2–T4 noise")
}

func TestProgressBar(t *testing.T) {
	bar := ProgressBar(10, 0.5, "█", "░")
	require.Equal(t, "[█████░░░░░]", bar)
}

func TestTruncateCell(t *testing.T) {
	got := truncateCell("GHSA-very-long-advisory-id-here", 12)
	require.LessOrEqual(t, displayWidth(got), 12)
}
