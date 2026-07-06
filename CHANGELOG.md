# Changelog

All notable changes to Depfuse are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [Unreleased]

---

## [1.0.0]

First tagged release. This pass makes exploit-evidence triage claims precise, scan coverage honest, and evidence confidence properly hedged — without adding app-reachability analysis (still out of scope; see [Roadmap](https://falc0n-researcher.github.io/depfuse-oss/roadmap/)).

### Added

- **Coverage banner** — every scan reports lockfile/registry-tree/OSV-index completeness (`meta.coverage`), including which snapshot mode served it (`online`, `full-offline-db`, or `embedded-snapshot`) and a peer/optional-dependency count
- **Unresolved dependency itemization** — packages that can't be pinned to a concrete version (private registry, auth required, not found, network error, offline mode) are listed with the specific reason in the CLI, HTML, and `unresolved` JSON array — never silently skipped
- **`--fail-on-coverage-warning`** — optionally gate CI on partial coverage, not just incomplete
- **WATCH verdict in scan mode** — P3 findings render as WATCH instead of being folded into OK; add `--fail-on P0,P1,watch` to gate on it (never fails CI by default)
- **`depfuse decisions explain <CVE>`** — shows a stored decision's evidence tier then vs. now and current reopen status
- **`pathConfidence`** on components — `exact` for npm's full dependency-path reconstruction, `low` for yarn/pnpm/bun's flat lockfile format; a flat-resolved chain renders with an `(unranked)` note
- **Install-time lifecycle script context** — preinstall/install/postinstall/prepare hooks on a package's latest published version are surfaced as non-scoring supply-chain context (never affects priority or verdict)
- **`depfuse doctor --ci` workflow hardening checks** — lints `.github/workflows/*.yml` for unpinned actions, `pull_request_target` triggers, missing/overly-broad `permissions:`, npm-publish steps using a long-lived token instead of OIDC, and curl|bash install patterns
- **JSON schema versioning** — `schemaVersion` field on scan output plus a real top-level `schemas/scan-result.schema.json`
- **SARIF run-level coverage properties** — coverage status, unresolved count, and peer-dependency count on the SARIF `run` object

### Changed

- Renamed the "Exploitable" label to **"Weaponized Exposure"** everywhere (CLI, HTML, JSON method name, docs, samples) — it was ambiguous about what was actually being claimed (P0+P1 dependency exposure, not app-level exploitability)
- GitHub PoC "verified" now requires ≥2 corroborating signals (exact CVE match in repo name/description, community attention, a real description) instead of a stars-alone heuristic; forks never qualify regardless of signal count
- Fixed pnpm lockfileVersion 9 parsing — `packages:` keys dropped their leading `/` and previously parsed to zero packages
- This repo's own `.github/workflows/*.yml` and the `docs/ci.md` example are now SHA-pinned

### Fixed

- VulnCheck XDB citations now explicitly state they're citation-only and don't affect priority tier (behavior was already correct; the claim wasn't clear)

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
