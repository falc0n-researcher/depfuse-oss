package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultNPMRegistryURL = "https://registry.npmjs.org"

var npmRegistryBaseURL = defaultNPMRegistryURL

// SetNPMRegistryURLForTest overrides the npm registry base URL (tests only).
func SetNPMRegistryURLForTest(u string) {
	npmRegistryBaseURL = u
}

// FetchLatestVersion returns the semver published under the npm "latest" dist-tag.
func FetchLatestVersion(ctx context.Context, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("package name required")
	}
	reqURL := fmt.Sprintf("%s/%s/latest", strings.TrimSuffix(npmRegistryBaseURL, "/"), npmRegistryPath(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("package %q not found on npm registry", name)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("npm registry http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var meta struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("decode npm registry response: %w", err)
	}
	if meta.Version == "" {
		return "", fmt.Errorf("npm registry returned no version for %q", name)
	}
	return meta.Version, nil
}

// FetchVersions returns all published versions for a package from the npm
// registry, newest selection left to the caller.
func FetchVersions(ctx context.Context, name string) ([]string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("package name required")
	}
	reqURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(npmRegistryBaseURL, "/"), npmRegistryPath(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	// Abbreviated metadata is smaller and sufficient for the versions map.
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json, application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found on npm registry", name)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("npm registry http %d for %q", resp.StatusCode, name)
	}
	var meta struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decode npm registry response: %w", err)
	}
	out := make([]string, 0, len(meta.Versions))
	for v := range meta.Versions {
		out = append(out, v)
	}
	return out, nil
}

func npmRegistryPath(name string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
		}
	}
	return url.PathEscape(name)
}

// PackageExistsOnNPM reports whether a package name resolves on the npm registry.
func PackageExistsOnNPM(ctx context.Context, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	reqURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(npmRegistryBaseURL, "/"), npmRegistryPath(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// VersionManifest holds dependency declarations for one published version.
type VersionManifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// FetchVersionManifest returns dependency sections for name@version from the npm registry.
func FetchVersionManifest(ctx context.Context, name, version string) (VersionManifest, error) {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return VersionManifest{}, fmt.Errorf("package name and version required")
	}
	reqURL := fmt.Sprintf("%s/%s/%s", strings.TrimSuffix(npmRegistryBaseURL, "/"), npmRegistryPath(name), url.PathEscape(version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return VersionManifest{}, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return VersionManifest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return VersionManifest{}, fmt.Errorf("package %s@%s not found on npm registry", name, version)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return VersionManifest{}, fmt.Errorf("npm registry http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var meta VersionManifest
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return VersionManifest{}, fmt.Errorf("decode npm version manifest: %w", err)
	}
	return meta, nil
}

// NormalizeNPMPackageName maps common mistakes like budibase/server to @budibase/server.
func NormalizeNPMPackageName(ctx context.Context, name string) string {
	name = strings.TrimSpace(name)
	if name == "" || strings.HasPrefix(name, "@") || !strings.Contains(name, "/") {
		return name
	}
	scoped := "@" + name
	if PackageExistsOnNPM(ctx, scoped) && !PackageExistsOnNPM(ctx, name) {
		return scoped
	}
	return name
}
