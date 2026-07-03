package feeds

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"gopkg.in/yaml.v3"
)

const nucleiRepo = "https://github.com/projectdiscovery/nuclei-templates.git"

var cveInText = regexp.MustCompile(`CVE-\d{4}-\d+`)
var cveInMeta = cveInText

// Nuclei ingests Nuclei template CVE references via cached git clone.
type Nuclei struct {
	CacheDir string
}

func (f *Nuclei) Name() string { return "NUCLEI" }

func (f *Nuclei) Fetch(ctx context.Context, runID string) ([]intel.NormalizedRecord, error) {
	dir := filepath.Join(f.CacheDir, "nuclei-templates")
	if _, err := os.Stat(filepath.Join(dir, ".git")); os.IsNotExist(err) {
		if err := os.MkdirAll(f.CacheDir, 0o755); err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", nucleiRepo, dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("nuclei clone: %w: %s", err, out)
		}
	} else {
		cmd := exec.CommandContext(ctx, "git", "-C", dir, "pull", "--ff-only")
		_ = cmd.Run()
	}
	now := time.Now().UTC()
	type nucleiHit struct {
		id      string
		relPath string
	}
	byCVE := map[string]nucleiHit{}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		templateID, cves := extractNucleiCVEs(data)
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		for _, cve := range cves {
			if _, ok := byCVE[cve]; !ok {
				byCVE[cve] = nucleiHit{id: templateID, relPath: rel}
			}
		}
		return nil
	})
	var out []intel.NormalizedRecord
	for cve, hit := range byCVE {
		tid := hit.id
		if tid == "" {
			tid = cve
		}
		out = append(out, intel.NormalizedRecord{
			CanonicalID: cve,
			Aliases:     []intel.AliasInput{{Alias: cve, AliasType: "CVE"}},
			Artifact: intel.ArtifactInput{
				ID: "NUCLEI:" + cve, Source: models.SourceNuclei, TrustClass: models.TrustHigh,
				Title: "Nuclei template: " + tid, URL: NucleiBlobURL(hit.relPath),
				ObservedAt: now, FeedRunID: runID, NucleiTemplate: tid,
				Extra: map[string]string{"templatePath": hit.relPath},
			},
		})
	}
	return out, nil
}

type nucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string `yaml:"name"`
		Description    string `yaml:"description"`
		Tags           string `yaml:"tags"`
		Classification struct {
			CVEID yaml.Node `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
}

func extractNucleiCVEs(data []byte) (templateID string, cves []string) {
	var tmpl nucleiTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return "", nil
	}
	templateID = tmpl.ID
	seen := map[string]bool{}
	addCVEIDsFromYAMLNode(tmpl.Info.Classification.CVEID, seen, &cves)
	for _, field := range []string{tmpl.Info.Name, tmpl.Info.Description, tmpl.Info.Tags} {
		for _, cve := range cveInMeta.FindAllString(field, -1) {
			if !seen[cve] {
				seen[cve] = true
				cves = append(cves, cve)
			}
		}
	}
	return templateID, cves
}

func addCVEIDsFromYAMLNode(node yaml.Node, seen map[string]bool, cves *[]string) {
	switch node.Kind {
	case yaml.ScalarNode:
		cve := strings.TrimSpace(node.Value)
		if cveInMeta.MatchString(cve) && !seen[cve] {
			seen[cve] = true
			*cves = append(*cves, cve)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			addCVEIDsFromYAMLNode(*child, seen, cves)
		}
	}
}
