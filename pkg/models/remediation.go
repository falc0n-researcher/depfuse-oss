package models

// UpgradeJump is the semver distance from the installed version to the minimal
// published fix — the blast radius of the remediation upgrade.
type UpgradeJump string

const (
	JumpNone    UpgradeJump = ""        // no published fix at all
	JumpPatch   UpgradeJump = "patch"   // x.y.Z — safest
	JumpMinor   UpgradeJump = "minor"   // x.Y.z — usually safe
	JumpMajor   UpgradeJump = "major"   // X.y.z — likely breaking
	JumpUnknown UpgradeJump = "unknown" // versions unparseable, or fixes exist but none forward of installed
)

// Remediation describes how to fix a finding and how painful that fix is —
// the bridge from "this is risky" to "here is the cheapest safe action".
type Remediation struct {
	Installed    string      `json:"installed,omitempty"`
	FixVersion   string      `json:"fixVersion,omitempty"` // minimal published fix strictly newer than installed
	Jump         UpgradeJump `json:"jump,omitempty"`
	Breaking     bool        `json:"breaking,omitempty"` // true when the jump is a major bump
	FixAvailable bool        `json:"fixAvailable"`       // a usable forward fix exists
}

// Label is the compact human-readable remediation summary for the Fix column.
func (r Remediation) Label() string {
	if !r.FixAvailable {
		switch r.Jump {
		case JumpUnknown:
			return "see advisory"
		default:
			return "no fix yet"
		}
	}
	switch r.Jump {
	case JumpMajor:
		return r.FixVersion + " (major)"
	case JumpMinor:
		return r.FixVersion + " (minor)"
	case JumpPatch:
		return r.FixVersion + " (patch)"
	default:
		return r.FixVersion
	}
}

// UpgradeLine is the verbose one-line remediation directive.
func (r Remediation) UpgradeLine(pkg string) string {
	if !r.FixAvailable {
		if r.Jump == JumpUnknown {
			return "No clean forward upgrade — see advisory for the fixed branch"
		}
		return "No fixed version published yet — pin/override or remove the dependency"
	}
	switch r.Jump {
	case JumpMajor:
		return "Upgrade " + pkg + " " + r.Installed + " → " + r.FixVersion + " (major — review breaking changes)"
	case JumpMinor:
		return "Upgrade " + pkg + " " + r.Installed + " → " + r.FixVersion + " (minor)"
	case JumpPatch:
		return "Upgrade " + pkg + " " + r.Installed + " → " + r.FixVersion + " (patch — low risk)"
	default:
		return "Upgrade " + pkg + " " + r.Installed + " → " + r.FixVersion
	}
}
