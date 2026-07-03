package cli

import (
	"bufio"
	"os"
	"strings"
)

// loadDotEnv reads KEY=VALUE pairs from .env files without overriding existing env.
// Searches the current directory, then parents up to three levels.
func loadDotEnv() {
	if os.Getenv("DEPFUSE_VULNCHECK_TOKEN") != "" {
		return
	}
	for _, path := range dotEnvPaths() {
		if err := parseDotEnvFile(path); err != nil {
			continue
		}
		if os.Getenv("DEPFUSE_VULNCHECK_TOKEN") != "" {
			return
		}
	}
}

func dotEnvPaths() []string {
	dir, err := os.Getwd()
	if err != nil {
		return []string{".env"}
	}
	var paths []string
	for i := 0; i < 4 && dir != ""; i++ {
		paths = append(paths, dir+"/.env")
		dir = parentDir(dir)
	}
	return paths
}

func parentDir(path string) string {
	i := strings.LastIndex(path, string(os.PathSeparator))
	if i <= 0 {
		return ""
	}
	return path[:i]
}

func parseDotEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		if key == "" || os.Getenv(key) != "" {
			continue
		}
		_ = os.Setenv(key, val)
	}
	if key := "VULNCHECK_TOKEN"; os.Getenv("DEPFUSE_VULNCHECK_TOKEN") == "" {
		if v := os.Getenv(key); v != "" {
			_ = os.Setenv("DEPFUSE_VULNCHECK_TOKEN", v)
		}
	}
	return scanner.Err()
}
