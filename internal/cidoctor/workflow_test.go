package cidoctor_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/internal/cidoctor"
	"github.com/stretchr/testify/require"
)

func writeWorkflow(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

func hasMessage(findings []cidoctor.Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func TestLintDirNoWorkflowsDir(t *testing.T) {
	root := t.TempDir()
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	require.Empty(t, findings)
}

func TestLintDirDetectsUnpinnedAction(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "ci.yml", `
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test
`)
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	require.True(t, hasMessage(findings, "actions/checkout@v4 is not pinned"), "%+v", findings)
}

func TestLintDirAcceptsSHAPinnedAction(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "ci.yml", `
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
      - run: make test
`)
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	for _, f := range findings {
		require.NotContains(t, f.Message, "not pinned")
	}
}

func TestLintDirDetectsPullRequestTarget(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "risky.yml", `
name: Risky
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	require.True(t, hasMessage(findings, "pull_request_target"), "%+v", findings)
	for _, f := range findings {
		if strings.Contains(f.Message, "pull_request_target") {
			require.Equal(t, cidoctor.SeverityHigh, f.Severity)
		}
	}
}

func TestLintDirDetectsMissingPermissions(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "noperms.yml", `
name: NoPerms
on:
  push:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	require.True(t, hasMessage(findings, "no permissions"), "%+v", findings)
}

func TestLintDirDetectsWriteAll(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "writeall.yml", `
name: WriteAll
on:
  push:
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	require.True(t, hasMessage(findings, "write-all"), "%+v", findings)
}

func TestLintDirDetectsNPMPublishWithToken(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "publish.yml", `
name: Publish
on:
  push:
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
`)
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	require.True(t, hasMessage(findings, "long-lived token"), "%+v", findings)
}

func TestLintDirNPMPublishWithOIDCIsClean(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "publish.yml", `
name: Publish
on:
  push:
permissions:
  contents: read
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
`)
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	for _, f := range findings {
		require.NotContains(t, f.Message, "long-lived token")
	}
}

func TestLintDirDetectsCurlBash(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "install.yml", `
name: Install
on:
  push:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sSL https://example.com/install.sh | bash
`)
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	require.True(t, hasMessage(findings, "curl download"), "%+v", findings)
}

func TestLintDirCleanWorkflowHasNoFindings(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "clean.yml", `
name: Clean
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
      - run: make test
`)
	findings, err := cidoctor.LintDir(root)
	require.NoError(t, err)
	require.Empty(t, findings)
}
