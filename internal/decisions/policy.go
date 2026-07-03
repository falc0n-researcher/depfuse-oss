package decisions

import (
	"fmt"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const epssReopenThreshold = 0.90

// ShouldReopen evaluates stored reopen policy against current exploit evidence.
func ShouldReopen(d models.StoredDecision, curr models.Classification) (bool, string) {
	policy := d.ReopenPolicy
	if len(policy) == 0 {
		policy = models.DefaultReopenPolicy
	}
	prev := d.DecidedWhenLevel
	currLevel := curr.Priority
	prevSig := d.DecidedWhenSignals
	currSig := curr.Signals

	for _, trigger := range policy {
		switch trigger {
		case models.ReopenLevelIncrease:
			if levelIncreaseReopen(prev, currLevel) {
				return true, fmt.Sprintf("level changed %s → %s", prev, currLevel)
			}
		case models.ReopenKEVAdded:
			if !prevSig.KEV && currSig.KEV {
				return true, "KEV listing added since decision"
			}
		case models.ReopenMetasploitAdded:
			if !prevSig.Metasploit && currSig.Metasploit {
				return true, "Metasploit module added since decision"
			}
		case models.ReopenNucleiAdded:
			if !prevSig.Nuclei && currSig.Nuclei {
				return true, "Nuclei template added since decision"
			}
		case models.ReopenExploitArtifactAdded:
			if exploitArtifactAdded(prevSig, currSig) {
				return true, "exploit artifact added since decision"
			}
		case models.ReopenEPSSThreshold:
			if epssCrossedThreshold(prevSig.EPSS, currSig.EPSS) {
				return true, fmt.Sprintf("EPSS crossed %.2f (%.2f → %.2f)", epssReopenThreshold, prevSig.EPSS, currSig.EPSS)
			}
		}
	}
	return false, ""
}

// levelIncreaseReopen implements product reopen rules; Quiet→Watch stays silent.
func levelIncreaseReopen(prev, curr models.Priority) bool {
	if curr >= prev {
		return false
	}
	if prev == models.PriorityP4 && curr == models.PriorityP3 {
		return false
	}
	return true
}

func exploitArtifactAdded(prev, curr models.Signals) bool {
	if (!prev.Nuclei && curr.Nuclei) || (!prev.Metasploit && curr.Metasploit) {
		return true
	}
	if !prev.PoCVerified && curr.PoCVerified {
		return true
	}
	return false
}

func epssCrossedThreshold(prev, curr float64) bool {
	return prev < epssReopenThreshold && curr >= epssReopenThreshold
}
