package ignore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const fileName = ".depfuseignore"

// Rule suppresses matching findings from CI and default CLI output.
type Rule struct {
	ID      string `yaml:"id"`
	Package string `yaml:"package,omitempty"`
	Reason  string `yaml:"reason,omitempty"`
}

// File is the parsed ignore configuration.
type File struct {
	Findings []Rule `yaml:"findings"`
}

// Rules is a merged set of suppression rules.
type Rules struct {
	rules []Rule
}

// Load walks from scanRoot up to the git root (or filesystem root) and merges rules.
func Load(scanRoot string) (Rules, error) {
	root, err := filepath.Abs(scanRoot)
	if err != nil {
		return Rules{}, err
	}
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		root = filepath.Dir(root)
	}

	var merged File
	dir := root
	for {
		path := filepath.Join(dir, fileName)
		if data, err := os.ReadFile(path); err == nil {
			var f File
			if err := yaml.Unmarshal(data, &f); err != nil {
				return Rules{}, fmt.Errorf("%s: %w", path, err)
			}
			merged.Findings = append(merged.Findings, f.Findings...)
		}
		if isGitRoot(dir) {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return Rules{rules: merged.Findings}, nil
}

func isGitRoot(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// Match returns a suppression reason when the finding is ignored.
func (r Rules) Match(f models.Finding) (string, bool) {
	for _, rule := range r.rules {
		if !idMatches(rule.ID, f.CveMatch) {
			continue
		}
		if rule.Package != "" && !packageMatches(rule.Package, f.Component) {
			continue
		}
		reason := strings.TrimSpace(rule.Reason)
		if reason == "" {
			reason = "suppressed by .depfuseignore"
		}
		return reason, true
	}
	return "", false
}

func idMatches(ruleID string, c models.CveMatch) bool {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return false
	}
	ids := append([]string{c.CVEID, c.OSVID, c.GHSAID}, c.Aliases...)
	for _, id := range ids {
		if strings.EqualFold(strings.TrimSpace(id), ruleID) {
			return true
		}
	}
	return false
}

func packageMatches(spec string, comp models.Component) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	if idx := strings.Index(spec, "@"); idx >= 0 {
		name := spec[:idx]
		ver := spec[idx+1:]
		if !strings.EqualFold(comp.Name, name) {
			return false
		}
		if ver == "" || ver == "*" {
			return true
		}
		return comp.Version == ver
	}
	return strings.EqualFold(comp.Name, spec)
}

// Apply marks matching findings as suppressed.
func Apply(findings []models.Finding, rules Rules) []models.Finding {
	out := make([]models.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if reason, ok := rules.Match(out[i]); ok {
			out[i].Suppressed = true
			out[i].SuppressionReason = reason
		}
	}
	return out
}

// Partition splits active and suppressed findings.
func Partition(findings []models.Finding) (active, suppressed []models.Finding) {
	for _, f := range findings {
		if f.Suppressed {
			suppressed = append(suppressed, f)
			continue
		}
		active = append(active, f)
	}
	return active, suppressed
}
