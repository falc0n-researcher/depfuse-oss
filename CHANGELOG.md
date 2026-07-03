# Changelog

All notable changes to Depfuse are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [Unreleased]

---

## [0.1.x]

### Added

- **Decision memory** — scan history persistence in `intel.db`, `depfuse watch` command, accepted-risk reopen policy
- **Verdict receipt chains** — `FIX NOW because:` bullets with cited artifact links on every actionable finding
- **VulnCheck KEV integration** — broader exploited-in-the-wild coverage with per-CVE exploitation citations
- **EPSS-shift tracking** — watch surfaces EPSS threshold crossings for accepted-risk findings
- **Lockfile coverage gate** — `SCAN INCOMPLETE` when no lockfile is present; always exits 1
- **`depfuse watch --format markdown`** — decision memory digest suitable for GitHub step summary
- **`depfuse doctor --ci`** — validate pinned intel setup for reproducible offline scans
- **Priority upgrade rollup** — CLI and HTML group transitive CVEs under declared dependencies with upgrade suggestions
- **`--out-dir` on `package` and `cve` modes** — auto-save HTML/MD reports to any path
- **Package dossier dedupe** — HTML dossiers show CVE table + single suggested upgrade path per package

### Changed

- KEV feed migrated from stock CISA JSON to VulnCheck Community KEV API
- Exploited-level briefings now cite VulnCheck exploitation evidence URLs

### Fixed

- Offline scans no longer print a false `matches will be empty` warning when `osv_cache` provides matches
- Reports now correctly update for package/cve modes when `--out-dir` is set

---

## [0.1.0]

### Added

- npm lockfile resolution — npm, yarn (v1 + Berry), pnpm, bun, workspaces, npm-shrinkwrap
- OSV advisory matching with alias fallback (GHSA ↔ CVE)
- Intelligence feeds: VulnCheck KEV, EPSS, Nuclei templates, Metasploit modules, Exploit-DB, PoC GitHub metadata
- Evidence classification — levels P0 (Actively Exploited) through P4 (Hygiene)
- Deterministic verdicts — FIX NOW / FIX SOON / OK based on evidence level and production/dev dependency scope
- Output formats: CLI tables, JSON, SARIF, Markdown, HTML single-page report
- Embedded offline snapshot — first scan works without `collect`
- `.depfuseignore` suppressions
- `depfuse doctor` — local setup validation
- `depfuse package` and `depfuse cve` lookup modes
- Remote scan via GitHub URL (`--repo` flag)
