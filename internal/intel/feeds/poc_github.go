package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

const defaultGitHubSearchURL = "https://api.github.com/search/repositories"

var githubSearchBaseURL = defaultGitHubSearchURL

// PoCGitHub discovers public PoC repositories via GitHub search (metadata only).
type PoCGitHub struct {
	CVEs []string
}

func (f *PoCGitHub) Name() string { return "POC_GITHUB" }

func (f *PoCGitHub) Fetch(ctx context.Context, runID string) ([]intel.NormalizedRecord, error) {
	if pocGitHubDisabled() {
		return nil, nil
	}
	if len(f.CVEs) == 0 {
		return nil, nil
	}
	token := os.Getenv("GITHUB_TOKEN")
	max := pocGitHubMax()
	if token == "" {
		max = minInt(max, 10)
	}
	if max > 0 && len(f.CVEs) > max {
		f.CVEs = f.CVEs[:max]
	}

	client := &http.Client{Timeout: 30 * time.Second}
	now := time.Now().UTC()
	seen := map[string]bool{}
	var out []intel.NormalizedRecord

	for _, cve := range f.CVEs {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		repos, err := searchGitHubPoC(ctx, client, token, cve)
		if err != nil {
			continue
		}
		for _, repo := range repos {
			key := cve + "|" + repo.FullName
			if seen[key] {
				continue
			}
			seen[key] = true
			maturity := models.MaturityHasCode
			signals := pocSignalCount(repo, cve)
			if !repo.Fork && signals >= 2 {
				maturity = models.MaturityVerified
			}
			out = append(out, intel.NormalizedRecord{
				CanonicalID: cve,
				Aliases:     []intel.AliasInput{{Alias: cve, AliasType: "CVE"}},
				Artifact: intel.ArtifactInput{
					ID:          fmt.Sprintf("POC_GITHUB:%s:%s", cve, repo.FullName),
					Source:      models.SourcePoCGitHub,
					TrustClass:  models.TrustLow,
					MaturityTag: maturity,
					Title:       "GitHub PoC: " + repo.FullName,
					URL:         repo.HTMLURL,
					ObservedAt:  now,
					FeedRunID:   runID,
					PoCRepo:     repo.FullName,
					PoCStars:    intPtr(repo.Stars),
					Extra: map[string]string{
						"cve":   cve,
						"stars": strconv.Itoa(repo.Stars),
					},
				},
			})
		}
		if token == "" {
			time.Sleep(6 * time.Second) // respect unauthenticated search rate limits
		}
	}
	return out, nil
}

type ghRepo struct {
	FullName    string
	HTMLURL     string
	Description string
	Stars       int
	Fork        bool
	CreatedAt   time.Time
}

type ghSearchResponse struct {
	Items []struct {
		FullName    string `json:"full_name"`
		HTMLURL     string `json:"html_url"`
		Description string `json:"description"`
		Stars       int    `json:"stargazers_count"`
		Fork        bool   `json:"fork"`
		CreatedAt   string `json:"created_at"`
	} `json:"items"`
}

// pocSignalCount corroborates a PoC repo's relevance to cve beyond raw star
// count — a starred repo alone is not evidence the code targets this specific
// vulnerability. Forks are excluded entirely by the caller (a mirror adds no
// independent corroboration). Verified status requires >= 2 of:
//   - the CVE id appears verbatim in the repo name or description (the author
//     is explicitly claiming this exploit, not an incidental keyword match)
//   - community attention (stars >= 10)
//   - the repo has a real description at all (distinguishes genuine writeups
//     from empty scraped/spam repos that only matched on README content)
func pocSignalCount(repo ghRepo, cve string) int {
	score := 0
	lowerCVE := strings.ToLower(cve)
	if strings.Contains(strings.ToLower(repo.FullName), lowerCVE) ||
		strings.Contains(strings.ToLower(repo.Description), lowerCVE) {
		score++
	}
	if repo.Stars >= 10 {
		score++
	}
	if strings.TrimSpace(repo.Description) != "" {
		score++
	}
	return score
}

func searchGitHubPoC(ctx context.Context, client *http.Client, token, cve string) ([]ghRepo, error) {
	q := url.QueryEscape(cve + " in:name,description,readme")
	reqURL := fmt.Sprintf("%s?q=%s&sort=stars&order=desc&per_page=3", githubSearchBaseURL, q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("github rate limit")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("github search http %d", resp.StatusCode)
	}
	var body ghSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	var out []ghRepo
	for _, item := range body.Items {
		if item.FullName == "" {
			continue
		}
		createdAt, _ := time.Parse(time.RFC3339, item.CreatedAt)
		out = append(out, ghRepo{
			FullName: item.FullName, HTMLURL: item.HTMLURL, Description: item.Description,
			Stars: item.Stars, Fork: item.Fork, CreatedAt: createdAt,
		})
	}
	return out, nil
}

func pocGitHubDisabled() bool {
	v := strings.TrimSpace(os.Getenv("DEPFUSE_POC_GITHUB"))
	return v == "0" || strings.EqualFold(v, "false")
}

func pocGitHubMax() int {
	v := os.Getenv("DEPFUSE_POC_GITHUB_MAX")
	if v == "" {
		return 50
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 50
	}
	return n
}

func intPtr(n int) *int { return &n }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
