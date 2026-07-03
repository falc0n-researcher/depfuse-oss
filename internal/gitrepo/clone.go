package gitrepo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var urlPattern = regexp.MustCompile(`(?i)^https?://github\.com/([^/]+)/([^/.]+)`)

// IsGitHubURL reports whether s is a shallow-cloneable github.com repository URL.
func IsGitHubURL(s string) bool {
	return urlPattern.MatchString(strings.TrimSuffix(s, ".git"))
}

// Clone performs a shallow clone of a GitHub repository and returns the local path.
// Cached clones are reused when the destination already exists.
func Clone(repoURL, ref string) (string, error) {
	m := urlPattern.FindStringSubmatch(strings.TrimSuffix(repoURL, ".git"))
	if m == nil {
		return "", fmt.Errorf("gitrepo: invalid GitHub URL %q", repoURL)
	}
	owner, repo := m[1], m[2]

	cacheRoot := filepath.Join(os.TempDir(), "depfuse-repos")
	if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
		return "", fmt.Errorf("gitrepo: create cache dir: %w", err)
	}

	dest := filepath.Join(cacheRoot, owner+"-"+repo)
	if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
		return dest, nil
	}

	args := []string{"clone", "--depth", "1", repoURL, dest}
	if ref != "" {
		args = []string{"clone", "--depth", "1", "--branch", ref, repoURL, dest}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gitrepo: clone failed: %w", err)
	}
	return dest, nil
}
