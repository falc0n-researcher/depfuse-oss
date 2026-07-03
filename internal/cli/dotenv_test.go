package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadDotEnvMapsVulnCheckToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(path, []byte("VULNCHECK_TOKEN=from-dotenv\n"), 0o600))

	origWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() {
		_ = os.Chdir(origWD)
		_ = os.Unsetenv("DEPFUSE_VULNCHECK_TOKEN")
		_ = os.Unsetenv("VULNCHECK_TOKEN")
	})
	_ = os.Unsetenv("DEPFUSE_VULNCHECK_TOKEN")
	_ = os.Unsetenv("VULNCHECK_TOKEN")

	loadDotEnv()
	require.Equal(t, "from-dotenv", os.Getenv("DEPFUSE_VULNCHECK_TOKEN"))
}
