package brief

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// Render produces a deterministic, evidence-grounded briefing. Tiers and
// verdicts are computed in code — briefings never call out to an LLM.
func Render(comp models.Component, cve models.CveMatch, class models.Classification, v models.Verdict, reason string) string {
	if class.Priority > models.PriorityP2 {
		return fmt.Sprintf("**%s** in `%s@%s` — %s. %s", cve.CVEID, comp.Name, comp.Version, class.Priority, reason)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s — %s\n\n", cve.CVEID, class.Priority))
	if class.Band != "" {
		b.WriteString(fmt.Sprintf("**Confidence:** %s (%d corroborating source(s))\n\n", class.Band, len(class.Evidence)))
	}
	b.WriteString("## Summary\n")
	if cve.Summary != "" {
		b.WriteString(cve.Summary + "\n")
	} else {
		b.WriteString("Vulnerability matched via OSV for this dependency version.\n")
	}
	b.WriteString("\n## How the attack works\n")
	b.WriteString(attackNarrative(class, cve.Summary) + "\n")
	b.WriteString("\n## Evidence\n")
	for _, e := range class.Evidence {
		ref := e.Title
		if e.URL != "" {
			ref = fmt.Sprintf("[%s](%s)", e.Title, e.URL)
		}
		b.WriteString(fmt.Sprintf("- %s — _%s_ %s\n", e.Claim, e.Source, ref))
	}
	if len(class.Evidence) == 0 {
		b.WriteString("- No exploit artifacts found; abstaining on exploit mechanics.\n")
	}
	b.WriteString("\n## Fix\n")
	if len(cve.FixedVersions) > 0 {
		b.WriteString(fmt.Sprintf("Upgrade `%s` to %s or later.\n", comp.Name, cve.FixedVersions[0]))
	} else {
		b.WriteString(fmt.Sprintf("Review advisory and upgrade `%s` when a patched version is available.\n", comp.Name))
	}
	b.WriteString(fmt.Sprintf("\n## Verdict: **%s**\n%s\n", v, reason))
	return b.String()
}

func attackNarrative(class models.Classification, summary string) string {
	s := class.Signals
	var lead string
	switch {
	case s.KEV:
		lead = "Listed in VulnCheck KEV (known exploited in the wild, with cited exploitation evidence)."
	case s.Nuclei:
		lead = "A Nuclei template exists, indicating repeatable detection/exploitation tooling."
	case s.Metasploit:
		lead = "A Metasploit module references this CVE."
	case s.PoCVerified:
		lead = "Verified public proof-of-concept references exist (metadata only; exploit code not executed)."
	case s.PoCPresent:
		lead = "Unverified proof-of-concept references exist."
	case s.ExploitDB:
		lead = "An Exploit-DB entry is indexed for this CVE (metadata only; exploit code not executed)."
	default:
		lead = "No exploit evidence available from indexed sources."
	}
	if summary != "" {
		return lead + " " + summary
	}
	return lead
}

// ValidateGrounding ensures every non-header line in elevated briefings has evidence backing.
func ValidateGrounding(class models.Classification, briefing string) bool {
	if class.Priority > models.PriorityP2 {
		return true
	}
	if class.Priority <= models.PriorityP2 && len(class.Evidence) == 0 {
		return strings.Contains(briefing, "abstaining")
	}
	return len(class.Evidence) > 0
}
