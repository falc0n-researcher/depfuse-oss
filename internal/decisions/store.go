package decisions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const dirName = ".depfuse"
const fileName = "decisions.yaml"

// File is a loaded decision corpus.
type File struct {
	Path      string
	Decisions []models.StoredDecision
}

// DefaultPath returns .depfuse/decisions.yaml under root.
func DefaultPath(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		root = filepath.Dir(root)
	}
	return filepath.Join(root, dirName, fileName), nil
}

// Load reads decisions from root/.depfuse/decisions.yaml (missing file is empty).
func Load(root string) (File, error) {
	path, err := DefaultPath(root)
	if err != nil {
		return File{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return File{Path: path}, nil
		}
		return File{}, err
	}
	var doc models.DecisionFile
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	return File{Path: path, Decisions: doc.Decisions}, nil
}

// Save writes the decision file, creating .depfuse/ if needed.
func Save(f File) error {
	if f.Path == "" {
		return fmt.Errorf("decisions: path required")
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
		return err
	}
	doc := models.DecisionFile{Decisions: f.Decisions}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(f.Path, data, 0o644)
}

// Add appends or replaces a matching decision entry.
func (f *File) Add(d models.StoredDecision) {
	d.CVE = strings.ToUpper(strings.TrimSpace(d.CVE))
	key := entryKey(d)
	for i := range f.Decisions {
		if entryKey(f.Decisions[i]) == key {
			f.Decisions[i] = d
			return
		}
	}
	f.Decisions = append(f.Decisions, d)
}

func entryKey(d models.StoredDecision) string {
	pkg := strings.ToLower(strings.TrimSpace(d.Package))
	ver := strings.TrimSpace(d.Version)
	if pkg == "" {
		return d.CVE
	}
	if ver == "" {
		return d.CVE + ":" + pkg
	}
	return d.CVE + ":" + pkg + "@" + ver
}

// Match returns the most specific stored decision for a finding.
func (f File) Match(finding models.Finding) (models.StoredDecision, bool) {
	cve := strings.ToUpper(strings.TrimSpace(finding.CveMatch.CVEID))
	if cve == "" {
		cve = strings.ToUpper(strings.TrimSpace(finding.CveMatch.AdvisoryID()))
	}
	var best *models.StoredDecision
	bestScore := -1
	for i := range f.Decisions {
		d := &f.Decisions[i]
		if !strings.EqualFold(d.CVE, cve) {
			continue
		}
		score := matchScore(d, finding)
		if score < 0 {
			continue
		}
		if score > bestScore {
			best = d
			bestScore = score
		}
	}
	if best == nil {
		return models.StoredDecision{}, false
	}
	return *best, true
}

func matchScore(d *models.StoredDecision, f models.Finding) int {
	if !strings.EqualFold(d.CVE, f.CveMatch.CVEID) && !strings.EqualFold(d.CVE, f.CveMatch.AdvisoryID()) {
		return -1
	}
	pkg := strings.TrimSpace(d.Package)
	ver := strings.TrimSpace(d.Version)
	if pkg == "" {
		return 0
	}
	if !strings.EqualFold(pkg, f.Component.Name) {
		return -1
	}
	if ver == "" || ver == "*" {
		return 1
	}
	if f.Component.Version == ver {
		return 2
	}
	return -1
}

// Remove deletes a decision by CVE and optional package@version scope.
func (f *File) Remove(cve, pkg, version string) bool {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	target := entryKey(models.StoredDecision{CVE: cve, Package: pkg, Version: version})
	out := f.Decisions[:0]
	removed := false
	for _, d := range f.Decisions {
		if entryKey(d) == target {
			removed = true
			continue
		}
		out = append(out, d)
	}
	f.Decisions = out
	return removed
}

// Normalize fills defaults on load/write.
func Normalize(d *models.StoredDecision) {
	if d.DecidedAt.IsZero() {
		d.DecidedAt = time.Now().UTC()
	}
	if len(d.ReopenPolicy) == 0 {
		d.ReopenPolicy = models.DefaultReopenPolicy
	}
}

// MarshalYAML encodes a decision file document.
func MarshalYAML(doc models.DecisionFile) ([]byte, error) {
	return yaml.Marshal(doc)
}
