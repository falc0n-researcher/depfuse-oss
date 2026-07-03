package intel

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

// SeedDemoData loads representative intelligence for tests, offline demo, and CFP booth scans.
func SeedDemoData(s *Store) error {
	now := time.Now().UTC()
	artifacts := []models.RawArtifact{
		// ── CFP demo_package highlights ──────────────────────────────────────
		{
			ID: "kev-CVE-2025-29927", CVEID: "CVE-2025-29927", Source: models.SourceKEV,
			TrustClass: models.TrustAuthoritative, Title: "VulnCheck KEV: Next.js middleware bypass",
			URL: "https://vulncheck.com/kev", ObservedAt: now,
		},
		{
			ID: "nuclei-CVE-2025-29927", CVEID: "CVE-2025-29927", Source: models.SourceNuclei,
			TrustClass: models.TrustHigh, Title: "Nuclei template: CVE-2025-29927",
			URL:        "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-29927.yaml",
			ObservedAt: now,
			Metadata: map[string]string{
				"templateId":   "CVE-2025-29927",
				"templatePath": "http/cves/2025/CVE-2025-29927.yaml",
			},
		},
		{
			ID: "edb-CVE-2019-11358", CVEID: "CVE-2019-11358", Source: models.SourceExploitDB,
			TrustClass: models.TrustMedium, Title: "Exploit-DB: jQuery prototype pollution",
			URL: "https://www.exploit-db.com/exploits/52141", ObservedAt: now,
			Metadata: map[string]string{"edbId": "52141"},
		},
		{
			ID: "epss-CVE-2019-11358", CVEID: "CVE-2019-11358", Source: models.SourceEPSS,
			TrustClass: models.TrustMedium, Title: "EPSS score",
			ObservedAt: now, Metadata: map[string]string{"score": "0.08"},
		},
		// ── Regression / classify fixtures ───────────────────────────────────
		{
			ID: "kev-CVE-2021-44228", CVEID: "CVE-2021-44228", Source: models.SourceKEV,
			TrustClass: models.TrustAuthoritative, Title: "VulnCheck KEV: Log4Shell",
			URL: "https://vulncheck.com/kev", ObservedAt: now,
		},
		{
			ID: "nuclei-CVE-2021-44228", CVEID: "CVE-2021-44228", Source: models.SourceNuclei,
			TrustClass: models.TrustHigh, Title: "Nuclei template: CVE-2021-44228",
			URL: "https://github.com/projectdiscovery/nuclei-templates", ObservedAt: now,
			Metadata: map[string]string{"templateId": "CVE-2021-44228"},
		},
		{
			ID: "kev-CVE-2022-22965", CVEID: "CVE-2022-22965", Source: models.SourceKEV,
			TrustClass: models.TrustAuthoritative, Title: "VulnCheck KEV: Spring4Shell",
			URL: "https://vulncheck.com/kev", ObservedAt: now,
		},
		{
			ID: "msf-CVE-2022-22965", CVEID: "CVE-2022-22965", Source: models.SourceMetasploit,
			TrustClass: models.TrustHigh, Title: "Metasploit module: Spring Core RCE",
			URL: "https://github.com/rapid7/metasploit-framework", ObservedAt: now,
			Metadata: map[string]string{"module": "exploit/multi/http/spring_core_rce"},
		},
		{
			ID: "poc-CVE-2020-8209", CVEID: "CVE-2020-8209", Source: models.SourcePoCGitHub,
			TrustClass: models.TrustLow, MaturityTag: models.MaturityHasCode,
			Title: "Unverified GitHub PoC", URL: "https://github.com/example/poc-cve-2020-8209", ObservedAt: now,
		},
		{
			ID: "epss-CVE-2020-8209", CVEID: "CVE-2020-8209", Source: models.SourceEPSS,
			TrustClass: models.TrustMedium, Title: "EPSS score",
			ObservedAt: now, Metadata: map[string]string{"score": "0.12"},
		},
		{
			ID: "epss-CVE-2023-26136", CVEID: "CVE-2023-26136", Source: models.SourceEPSS,
			TrustClass: models.TrustMedium, Title: "EPSS score",
			ObservedAt: now, Metadata: map[string]string{"score": "0.02"},
		},
	}
	for _, a := range artifacts {
		if err := s.UpsertArtifact(a); err != nil {
			return fmt.Errorf("seed artifact %s: %w", a.ID, err)
		}
	}
	if err := SeedDemoAliasLinks(s); err != nil {
		return err
	}
	if err := SeedDemoOSVPayloads(s); err != nil {
		return err
	}
	return SeedDemoPackageMeta(s, now)
}

// SeedDemoPackageMeta pins npm registry metadata for offline demo HTML reports.
func SeedDemoPackageMeta(s *Store, at time.Time) error {
	pkgs := []models.PackageContext{
		{
			Name:            "next",
			Description:     "The React Framework for production — hybrid static & server rendering, TypeScript support, smart bundling, and more.",
			WeeklyDownloads: 5_800_000,
			License:         "MIT",
			Homepage:        "https://nextjs.org",
			Popularity:      models.PopularityUbiquitous,
		},
		{
			Name:            "express",
			Description:     "Fast, unopinionated, minimalist web framework for Node.js.",
			WeeklyDownloads: 28_000_000,
			License:         "MIT",
			Homepage:        "https://expressjs.com",
			Popularity:      models.PopularityUbiquitous,
		},
		{
			Name:            "jquery",
			Description:     "jQuery is a fast, small, and feature-rich JavaScript library for DOM manipulation and AJAX.",
			WeeklyDownloads: 7_200_000,
			License:         "MIT",
			Homepage:        "https://jquery.com",
			Popularity:      models.PopularityUbiquitous,
		},
		{
			Name:            "lodash",
			Description:     "A modern JavaScript utility library delivering modularity, performance, & extras.",
			WeeklyDownloads: 45_000_000,
			License:         "MIT",
			Homepage:        "https://lodash.com",
			Popularity:      models.PopularityUbiquitous,
		},
		{
			Name:            "axios",
			Description:     "Promise based HTTP client for the browser and Node.js.",
			WeeklyDownloads: 52_000_000,
			License:         "MIT",
			Homepage:        "https://axios-http.com",
			Popularity:      models.PopularityUbiquitous,
		},
		{
			Name:            "body-parser",
			Description:     "Node.js body parsing middleware.",
			WeeklyDownloads: 35_000_000,
			License:         "MIT",
			Popularity:      models.PopularityUbiquitous,
		},
	}
	for _, p := range pkgs {
		copy := p
		if err := s.PutPackageMeta(p.Name, &copy, at); err != nil {
			return fmt.Errorf("seed package meta %s: %w", p.Name, err)
		}
	}
	return nil
}

// SeedDemoAliasLinks merges OSV GHSA rows with seeded CVE artifacts for offline demo scans.
func SeedDemoAliasLinks(s *Store) error {
	links := []struct{ alias, canonical string }{
		{"GHSA-f82v-jwr5-mffw", "CVE-2025-29927"}, // next.js middleware bypass
		{"GHSA-6c3j-c64m-qhgq", "CVE-2019-11358"}, // jQuery prototype pollution
		{"GHSA-gxr4-xjj5-5px2", "CVE-2020-11022"}, // jQuery XSS
		{"GHSA-jpcq-cgw6-v4j6", "CVE-2020-11023"}, // jQuery XSS
		{"GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"}, // lodash command injection
		{"GHSA-hrpp-h998-j3pp", "CVE-2022-24999"}, // qs prototype pollution
		{"GHSA-qwcr-r2fm-qrc7", "CVE-2024-45590"}, // body-parser DoS
		{"GHSA-rv95-896h-c2vc", "CVE-2024-29041"}, // express open redirect
		{"GHSA-qx2v-qp2m-jg93", "CVE-2026-41305"}, // postcss
	}
	for _, l := range links {
		if err := s.UpsertAlias(l.canonical, l.canonical); err != nil {
			return fmt.Errorf("alias canonical %s: %w", l.canonical, err)
		}
		if err := s.UpsertAlias(l.alias, l.canonical); err != nil {
			return fmt.Errorf("alias link %s: %w", l.alias, err)
		}
	}
	return nil
}

// demoOSVGHSAIDs are fetched for npm semver fix ranges used in offline demo scans.
var demoOSVGHSAIDs = []string{
	"GHSA-f82v-jwr5-mffw", "GHSA-4342-x723-ch2f", "GHSA-c4j6-fc7j-m34r", // next
	"GHSA-6c3j-c64m-qhgq", "GHSA-gxr4-xjj5-5px2", "GHSA-jpcq-cgw6-v4j6", // jquery
	"GHSA-35jh-r3h4-6jhm", "GHSA-29mw-wpgm-hmr9", "GHSA-xxjr-mmjv-4gpg", // lodash
	"GHSA-hrpp-h998-j3pp", "GHSA-6rw7-vpxm-498p", "GHSA-w7fw-mjwx-w883", // qs
	"GHSA-qwcr-r2fm-qrc7", "GHSA-rv95-896h-c2vc", "GHSA-qw6h-vgh9-j6wx", // express chain
	"GHSA-m6fv-jmcg-4jfg", "GHSA-cm22-4g7w-348p", "GHSA-pxg6-pf52-xh8x", // express transitive
	"GHSA-37ch-88jc-xwx2", "GHSA-rhx6-c78j-4q9w", "GHSA-9wv6-86v2-598j", // path-to-regexp
}

// SeedDemoOSVPayloads fetches full OSV advisories for demo CVEs (fix versions + offline enrich).
// GHSA ids are fetched because they include npm semver fix ranges; CVE-only records often
// carry GIT commit ranges without semver fixes.
func SeedDemoOSVPayloads(s *Store) error {
	client := &http.Client{Timeout: 30 * time.Second}
	for _, id := range demoOSVGHSAIDs {
		payload, err := fetchOSVVuln(context.Background(), client, osvVulnURL, id)
		if err != nil {
			return fmt.Errorf("fetch osv %s: %w", id, err)
		}
		if err := s.storeOSVVulnPayload(id, payload); err != nil {
			return fmt.Errorf("store osv %s: %w", id, err)
		}
	}
	return nil
}
