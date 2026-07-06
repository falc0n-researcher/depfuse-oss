package pkgmeta

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

const (
	defaultRegistry     = "https://registry.npmjs.org"
	defaultDownloadsAPI = "https://api.npmjs.org/downloads/point/last-week"
)

var (
	registryBase  = defaultRegistry
	downloadsBase = defaultDownloadsAPI
	httpClient    = &http.Client{Timeout: 15 * time.Second}
)

// SetRegistryURLForTest overrides the npm registry base URL.
func SetRegistryURLForTest(u string) { registryBase = u }

// SetDownloadsURLForTest overrides the npm downloads API base URL.
func SetDownloadsURLForTest(u string) { downloadsBase = u }

// SetHTTPClientForTest overrides the HTTP client (tests only).
func SetHTTPClientForTest(c *http.Client) { httpClient = c }

func resetTestHooks() {
	registryBase = defaultRegistry
	downloadsBase = defaultDownloadsAPI
	httpClient = &http.Client{Timeout: 15 * time.Second}
}

type registryDoc struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	License     any    `json:"license"`
	Homepage    string `json:"homepage"`
	DistTags    struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
	Versions map[string]struct {
		Scripts map[string]string `json:"scripts"`
	} `json:"versions"`
}

// lifecycleHooks are the npm install-time script hooks worth surfacing as
// supply-chain context. See https://docs.npmjs.com/cli/using-npm/scripts.
var lifecycleHooks = []string{"preinstall", "install", "postinstall", "prepare"}

// lifecycleScriptNames returns which lifecycleHooks are present in scripts,
// preserving hook order.
func lifecycleScriptNames(scripts map[string]string) []string {
	var out []string
	for _, hook := range lifecycleHooks {
		if _, ok := scripts[hook]; ok {
			out = append(out, hook)
		}
	}
	return out
}

type downloadPoint struct {
	Package   string `json:"package"`
	Downloads int64  `json:"downloads"`
}

// FetchRegistry fetches package description, license, homepage, and
// install-time lifecycle script hooks (from the latest published version)
// from npm.
func FetchRegistry(ctx context.Context, name string) (description, license, homepage string, lifecycleScripts []string, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", "", nil, fmt.Errorf("package name required")
	}
	reqURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(registryBase, "/"), registryPath(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", "", "", nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", "", "", nil, fmt.Errorf("package %q not found on npm", name)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", "", "", nil, fmt.Errorf("npm registry http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var doc registryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", "", "", nil, fmt.Errorf("decode npm registry: %w", err)
	}
	if latest, ok := doc.Versions[doc.DistTags.Latest]; ok {
		lifecycleScripts = lifecycleScriptNames(latest.Scripts)
	}
	return strings.TrimSpace(doc.Description), formatLicense(doc.License), strings.TrimSpace(doc.Homepage), lifecycleScripts, nil
}

// FetchWeeklyDownloads returns last-week download counts for each package name.
func FetchWeeklyDownloads(ctx context.Context, names []string) (map[string]int64, error) {
	out := make(map[string]int64, len(names))
	if len(names) == 0 {
		return out, nil
	}
	encoded := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		encoded = append(encoded, url.PathEscape(n))
	}
	if len(encoded) == 0 {
		return out, nil
	}

	reqURL := downloadsBase + "/" + strings.Join(encoded, ",")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return out, fmt.Errorf("npm downloads http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}

	var points []downloadPoint
	if err := json.Unmarshal(body, &points); err != nil || len(points) == 0 {
		var single downloadPoint
		if err := json.Unmarshal(body, &single); err == nil && single.Package != "" {
			points = []downloadPoint{single}
		}
	}
	for _, p := range points {
		if p.Package != "" {
			out[p.Package] = p.Downloads
		}
	}
	return out, nil
}

func registryPath(name string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
		}
	}
	return url.PathEscape(name)
}

func formatLicense(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case map[string]any:
		if s, ok := t["type"].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
