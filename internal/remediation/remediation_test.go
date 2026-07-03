package remediation

import (
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func TestAssess(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		fixed     []string
		wantFix   string
		wantJump  models.UpgradeJump
		wantAvail bool
		wantBreak bool
	}{
		{
			name:      "patch bump",
			installed: "4.17.20",
			fixed:     []string{"4.17.21"},
			wantFix:   "4.17.21",
			wantJump:  models.JumpPatch,
			wantAvail: true,
		},
		{
			name:      "minor bump",
			installed: "3.2.1",
			fixed:     []string{"3.5.0"},
			wantFix:   "3.5.0",
			wantJump:  models.JumpMinor,
			wantAvail: true,
		},
		{
			name:      "major bump is breaking",
			installed: "15.1.0",
			fixed:     []string{"16.0.0"},
			wantFix:   "16.0.0",
			wantJump:  models.JumpMajor,
			wantAvail: true,
			wantBreak: true,
		},
		{
			name:      "picks smallest forward fix across branches",
			installed: "3.2.1",
			fixed:     []string{"1.12.3", "3.4.0", "4.0.0"},
			wantFix:   "3.4.0",
			wantJump:  models.JumpMinor,
			wantAvail: true,
		},
		{
			name:      "no published fix",
			installed: "1.0.0",
			fixed:     nil,
			wantJump:  models.JumpNone,
			wantAvail: false,
		},
		{
			name:      "fixes exist but none forward of installed is ambiguous",
			installed: "5.0.0",
			fixed:     []string{"2.2.2"},
			wantJump:  models.JumpUnknown,
			wantAvail: false,
		},
		{
			name:      "unparseable installed yields unknown jump but keeps fix",
			installed: "next",
			fixed:     []string{"3.5.0"},
			wantFix:   "3.5.0",
			wantJump:  models.JumpUnknown,
			wantAvail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Assess(tt.installed, tt.fixed)
			if r.FixVersion != tt.wantFix {
				t.Errorf("FixVersion = %q, want %q", r.FixVersion, tt.wantFix)
			}
			if r.Jump != tt.wantJump {
				t.Errorf("Jump = %q, want %q", r.Jump, tt.wantJump)
			}
			if r.FixAvailable != tt.wantAvail {
				t.Errorf("FixAvailable = %v, want %v", r.FixAvailable, tt.wantAvail)
			}
			if r.Breaking != tt.wantBreak {
				t.Errorf("Breaking = %v, want %v", r.Breaking, tt.wantBreak)
			}
		})
	}
}

func TestLabel(t *testing.T) {
	cases := map[string]models.Remediation{
		"4.17.21 (patch)": {FixVersion: "4.17.21", Jump: models.JumpPatch, FixAvailable: true},
		"16.0.0 (major)":  {FixVersion: "16.0.0", Jump: models.JumpMajor, FixAvailable: true, Breaking: true},
		"no fix yet":      {Jump: models.JumpNone},
		"see advisory":    {Jump: models.JumpUnknown},
	}
	for want, r := range cases {
		if got := r.Label(); got != want {
			t.Errorf("Label() = %q, want %q", got, want)
		}
	}
}
