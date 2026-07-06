// Package cidoctor lints GitHub Actions workflow files for supply-chain
// hardening gaps: unpinned third-party actions, risky pull_request_target
// triggers, missing/overly-broad permissions, npm-publish steps using a
// long-lived token instead of OIDC trusted publishing, and curl|bash
// install patterns. It is advisory context, separate from CVE findings —
// depfuse's core scan does not change based on these results.
package cidoctor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity ranks a workflow finding for CLI/exit-code purposes.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// Finding is one supply-chain hardening gap in a workflow file.
type Finding struct {
	File           string   `json:"file"`
	Severity       Severity `json:"severity"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation"`
}

var shaRef = regexp.MustCompile(`^[0-9a-f]{40}$`)
var curlBash = regexp.MustCompile(`curl[^\n|]*\|\s*(sudo\s+)?(bash|sh)\b`)

type workflowFile struct {
	On          any                    `yaml:"on"`
	Permissions any                    `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Permissions any            `yaml:"permissions"`
	Steps       []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	Env  map[string]any `yaml:"env"`
}

// LintDir parses every .github/workflows/*.yml (and .yaml) under root and
// returns supply-chain hardening findings, sorted by file then severity.
func LintDir(root string) ([]Finding, error) {
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		ff, err := lintWorkflow(name, data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		findings = append(findings, ff...)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})
	return findings, nil
}

func severityRank(s Severity) int {
	switch s {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	default:
		return 2
	}
}

func lintWorkflow(file string, data []byte) ([]Finding, error) {
	var wf workflowFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, err
	}

	var findings []Finding
	add := func(sev Severity, msg, rec string) {
		findings = append(findings, Finding{File: file, Severity: sev, Message: msg, Recommendation: rec})
	}

	if triggerNames(wf.On)["pull_request_target"] {
		add(SeverityHigh,
			"workflow triggers on pull_request_target",
			"pull_request_target runs with base-repo secrets and permissions against untrusted PR code — avoid it, or ensure the job never checks out/executes the PR head ref")
	}

	if !hasPermissions(wf.Permissions) {
		hasJobPerms := false
		for _, j := range wf.Jobs {
			if hasPermissions(j.Permissions) {
				hasJobPerms = true
				break
			}
		}
		if !hasJobPerms {
			add(SeverityLow,
				"no permissions: block set (workflow or job level)",
				"set least-privilege permissions explicitly (e.g. `permissions: contents: read`) instead of relying on the default GITHUB_TOKEN scope")
		}
	}
	if isWriteAll(wf.Permissions) {
		add(SeverityHigh, "permissions: write-all grants every scope", "replace with the specific scopes each job actually needs")
	}
	for jobName, j := range wf.Jobs {
		if isWriteAll(j.Permissions) {
			add(SeverityHigh, fmt.Sprintf("job %q sets permissions: write-all", jobName), "replace with the specific scopes this job actually needs")
		}
	}

	seenUnpinned := map[string]bool{}
	npmPublish := false
	npmTokenEnv := false
	idTokenWrite := hasIDTokenWrite(wf.Permissions)
	for _, j := range wf.Jobs {
		if hasIDTokenWrite(j.Permissions) {
			idTokenWrite = true
		}
		for _, step := range j.Steps {
			if step.Uses != "" && !isPinnedOrLocal(step.Uses) && !seenUnpinned[step.Uses] {
				seenUnpinned[step.Uses] = true
				add(SeverityMedium,
					fmt.Sprintf("%s is not pinned to a full commit SHA", step.Uses),
					"pin to a 40-character commit SHA (e.g. `uses: owner/action@<sha> # vX.Y.Z`) so the ref can't be moved to different code later")
			}
			if strings.Contains(step.Run, "npm publish") {
				npmPublish = true
			}
			for k := range step.Env {
				if isNPMTokenEnvKey(k) {
					npmTokenEnv = true
				}
			}
		}
	}
	if npmPublish && npmTokenEnv && !idTokenWrite {
		add(SeverityHigh,
			"npm publish uses a long-lived token (NPM_TOKEN/NODE_AUTH_TOKEN) instead of OIDC",
			"migrate to npm trusted publishing (OIDC) — add `permissions: id-token: write` and drop the token secret")
	}

	for _, j := range wf.Jobs {
		for _, step := range j.Steps {
			if curlBash.MatchString(step.Run) {
				add(SeverityLow,
					"step pipes a curl download directly into a shell",
					"download to a file, verify its checksum/signature, then execute — a curl|bash pattern can silently run whatever the remote host serves")
			}
		}
	}

	return findings, nil
}

// isPinnedOrLocal reports whether a `uses:` ref is already immutable: a
// full commit SHA, a local action (./path), or a Docker image reference
// (docker://), none of which need SHA-pinning the way a tag/branch ref does.
func isPinnedOrLocal(uses string) bool {
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return true
	}
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return false
	}
	return shaRef.MatchString(uses[at+1:])
}

func isNPMTokenEnvKey(key string) bool {
	k := strings.ToUpper(key)
	return k == "NPM_TOKEN" || k == "NODE_AUTH_TOKEN"
}

// triggerNames normalizes the `on:` field (string, list, or map — all valid
// YAML forms for GitHub Actions triggers) into a set of trigger names.
func triggerNames(on any) map[string]bool {
	out := map[string]bool{}
	switch v := on.(type) {
	case string:
		out[v] = true
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out[s] = true
			}
		}
	case map[string]any:
		for k := range v {
			out[k] = true
		}
	}
	return out
}

func hasPermissions(p any) bool {
	switch v := p.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case map[string]any:
		return len(v) > 0
	default:
		return false
	}
}

func isWriteAll(p any) bool {
	s, ok := p.(string)
	return ok && strings.TrimSpace(s) == "write-all"
}

func hasIDTokenWrite(p any) bool {
	m, ok := p.(map[string]any)
	if !ok {
		return false
	}
	v, ok := m["id-token"].(string)
	return ok && strings.TrimSpace(v) == "write"
}
