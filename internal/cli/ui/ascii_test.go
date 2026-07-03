package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrintableASCIIIgnoresComments(t *testing.T) {
	raw := "# comment\n  ART\n# tail\n"
	require.Equal(t, "  ART", printableASCII(raw))
}

func TestPrintHeaderIncludesArtAndSubtitle(t *testing.T) {
	var buf bytes.Buffer
	PrintHeader(&buf, "exploit-risk dependency scan")
	out := buf.String()
	require.Contains(t, out, "exploit-risk dependency scan")
	require.NotContains(t, out, "# Depfuse")
}

func TestPrintLogoAlwaysPrintsArt(t *testing.T) {
	art := printableASCII(asciiArtRaw)
	require.NotEmpty(t, art)

	var buf bytes.Buffer
	PrintLogo(&buf)
	require.True(t, strings.Contains(buf.String(), strings.Split(art, "\n")[0]))
}
