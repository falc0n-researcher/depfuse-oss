<div align="center">

# Depfuse

### Exploit-evidence decisions for npm dependency exposure.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev/)

</div>

---

Depfuse scans npm dependency exposure and classifies CVE matches by public exploit evidence. Instead of sorted vulnerability lists with risk scores, it produces **FIX NOW / FIX SOON / OK** verdicts with cited evidence receipts — so you know exactly why a finding is actionable and what to do about it.

The tool answers three questions:

1. **What can an attacker see?** — exact package versions pinned in your lockfile
2. **What has public exploit evidence?** — VulnCheck KEV, Nuclei templates, Metasploit modules, Exploit-DB entries, PoC metadata, EPSS scores
3. **Which prior decisions need revisiting?** — accepted-risk findings whose exploit picture has changed

Depfuse does **not** assess whether a CVE is reachable in your application's routes and code paths. It classifies dependency exposure by the strength of public exploit signals. App-context exploitability is planned for a future version.

---

## Install

```bash
go install github.com/falc0n-researcher/depfuse-oss/cmd/depfuse@latest
```

**Requirements:** Go 1.25+

The binary includes an embedded offline advisory index. A first scan works without any additional setup. Run `depfuse collect` to pull in the full OSV advisory inventory and fresh feed data.

---

## Commands

Three primary commands:

| Command | What it does |
|---------|--------------|
| `depfuse scan [path\|url]` | Scan a project directory or GitHub URL |
| `depfuse package name[@version]` | CVE lookup for a specific npm package |
| `depfuse cve CVE-YYYY-NNNNN` | Exploit-evidence classification for a specific CVE |

Additional commands:

| Command | What it does |
|---------|--------------|
| `depfuse collect` | Build `~/.depfuse/intel.db` from KEV, EPSS, Nuclei, Metasploit, Exploit-DB, OSV |
| `depfuse watch [path]` | Surface prior accepted-risk decisions whose evidence has changed |
| `depfuse decisions record/list` | Record and manage acceptance decisions |
| `depfuse doctor` | Validate local setup and intel database age |

---

## depfuse scan

Resolves all dependencies from a lockfile and classifies each CVE match by exploit evidence.

```bash
# Scan a local project
depfuse scan .
depfuse scan /path/to/project

# Scan with full transitive dependency tree in the output
depfuse scan . --tree

# Scan a remote GitHub repository
depfuse scan https://github.com/org/repo

# Output formats
depfuse scan . --format json
depfuse scan . --format sarif
depfuse scan . --format html

# Write HTML and Markdown reports to a directory
depfuse scan . --out-dir ./reports

# CI mode — suppress interactive output, explicit fail condition
depfuse scan . --ci --fail-on Exploited,Exploit-Ready
```

**Supported lockfiles:** `package-lock.json` · `npm-shrinkwrap.json` · `yarn.lock` (v1 + Berry) · `pnpm-lock.yaml` · `bun.lock` · npm workspaces

**No lockfile?** The scan is marked **SCAN INCOMPLETE** and exits with code 1. Transitive dependencies cannot be fully covered without a lockfile. Commit a lockfile for complete coverage.

**Sample output:**

```
  Input         ./my-app
  Lockfile      package-lock.json · 202 packages
  Scanned       3 Jul 2026 · 14:23 UTC

  Summary
  ┌─────────────┬─────────┬──────────┬────┬─────────┐
  │ Exploitable │ Fix Now │ Fix Soon │ OK │  Total  │
  ├─────────────┼─────────┼──────────┼────┼─────────┤
  │           1 │       1 │        1 │ 21 │      23 │
  └─────────────┴─────────┴──────────┴────┴─────────┘

  Action required (2)

  │ P0 · Exploited   │ CVE-2025-29927  │ next@15.1.0    │ KEV Nuc   │ FIX NOW  │
  │ P2 · Exploit Avail│ CVE-2019-11358  │ jquery@3.2.1   │ EDB       │ FIX SOON │

  FIX NOW because:
    • [KEV] Listed in VulnCheck KEV catalog
    • [Nuc] Nuclei scanner template exists
    • [Exposure] package-lock.json pins next@15.1.0 (production)
```

→ See [samples/scan.html](samples/scan.html) for the full HTML report.

---

## depfuse package

Looks up a specific npm package and version, resolves its dependency tree from the registry, and classifies all CVE matches.

```bash
# Look up a specific version
depfuse package next@15.1.0
depfuse package lodash@4.17.20

# Show per-CVE evidence detail
depfuse package next@15.1.0 --verbose

# Output formats
depfuse package next@15.1.0 --format json
depfuse package next@15.1.0 --format html --out-dir ./reports
```

→ See [samples/package.html](samples/package.html) for a sample HTML report.

---

## depfuse cve

Classifies a CVE by its public exploit evidence without requiring a project or lockfile.

```bash
# Classify a CVE
depfuse cve CVE-2025-29927

# Show dated evidence timeline
depfuse cve CVE-2025-29927 --timeline

# Output formats
depfuse cve CVE-2025-29927 --format json
depfuse cve CVE-2025-29927 --format html --out-dir ./reports
```

→ See [samples/cve.html](samples/cve.html) for a sample HTML report.

---

## Evidence levels

All CVE matches are classified into one of five levels based on the strength of public exploit evidence:

| Level | Label | Signal |
|-------|-------|--------|
| **P0** | Actively Exploited | VulnCheck KEV |
| **P1** | Weaponized | Nuclei template · Metasploit module · verified PoC |
| **P2** | Exploit Available | Exploit-DB entry · unverified PoC |
| **P3** | Low Exploitability | OSV match + EPSS ≥ 0.05, no exploit signal |
| **P4** | Hygiene | OSV match, no exploit signal, low or no EPSS |

**Invariant:** Unverified PoC cannot exceed P2. CVSS is not used as an exploit signal.

### Verdicts

| Verdict | Condition |
|---------|-----------|
| **FIX NOW** | P0 or P1 in production dependencies |
| **FIX SOON** | P2 or elevated watch band |
| **OK** | P3/P4, or P0/P1 scoped to dev-only dependencies |

Every actionable verdict includes cited evidence receipts:

```
FIX NOW because:
  • [KEV] Listed in VulnCheck KEV catalog — https://vulncheck.com/kev
  • [Nuc] Nuclei scanner template exists — https://github.com/projectdiscovery/nuclei-templates/...
  • [EPSS] Score 0.89
  • [Exposure] package-lock.json pins next@15.1.0 (production · direct)
```

Receipt tags: `[KEV]` `[Nuc]` `[MSF]` `[EDB]` `[PoC]` `[EPSS]` `[Exposure]`

---

## Intelligence sources

All feeds store **metadata only** — no exploit code or PoC files are downloaded or executed.

| Feed | Source | Trust |
|------|--------|-------|
| VulnCheck KEV | VulnCheck Community KEV API | Authoritative |
| Nuclei | projectdiscovery/nuclei-templates | High |
| Metasploit | Rapid7 modules_metadata_base.json | High |
| Exploit-DB | Offensive Security files_exploits.csv | Medium |
| PoC GitHub | GitHub Search API (title, URL, stars — metadata only) | Low |
| EPSS | FIRST epss_scores-current.csv.gz | Medium |
| OSV advisories | OSV API | Advisory baseline |

`depfuse collect` requires a free [VulnCheck Community](https://vulncheck.com/kev) token via `DEPFUSE_VULNCHECK_TOKEN`.

---

## Offline use

The binary ships with an embedded advisory index covering exploited and tooling-backed CVEs. First scans work without a network connection.

```bash
# Build or copy a full intel database
depfuse collect
cp ~/.depfuse/intel.db ./intel.db

# Use a pinned database
export DEPFUSE_INTEL_DB=./intel.db
export DEPFUSE_SKIP_AUTO_COLLECT=1
depfuse scan .
```

---

## Output formats

All three primary commands support `--format`:

| Format | Use case |
|--------|---------|
| `cli` (default) | Terminal output with color and tables |
| `json` | Structured output for automation |
| `html` | Single-page report with dependency tree, evidence table, upgrade rollup |
| `sarif` | Static analysis results for SARIF-compatible tooling |

Use `--out-dir <path>` to write HTML and Markdown reports to a directory alongside your project.

---

## Environment variables

| Variable | Purpose |
|----------|---------|
| `DEPFUSE_VULNCHECK_TOKEN` | VulnCheck Community API token for `collect` |
| `DEPFUSE_INTEL_DB` | Override the default `~/.depfuse/intel.db` path |
| `DEPFUSE_SKIP_AUTO_COLLECT` | Set to `1` to disable automatic 4-hour refresh |
| `DEPFUSE_OFFLINE` | Set to `1` to disable all network access |
| `DEPFUSE_COLLECT_TTL` | Auto-refresh interval in hours (default: 4) |
| `DEPFUSE_NO_COLOR` | Disable terminal color output |

---

## Decision memory

`depfuse watch` and `depfuse decisions` provide a lightweight decision layer on top of scan results.

```bash
# Record an accepted-risk decision
depfuse decisions record CVE-2019-11358 \
  --as accept \
  --reason "jquery only in internal admin, not exposed" \
  --package jquery --version 3.2.1

# Check which prior decisions need revisiting
depfuse watch .
```

Accepted findings stay silent on subsequent scans until a reopen condition triggers:

- CVE added to VulnCheck KEV after the decision was recorded
- Evidence level escalates (e.g. P3 → P1)
- EPSS crosses the 0.90 threshold

---

## What Depfuse is not

- **Not a CVE risk scorer** — Grype and Trivy already produce CVSS+EPSS weighted lists; Depfuse is a different tool for a different workflow
- **Not reachability analysis** — it does not determine whether vulnerable code is called in your application
- **Not multi-ecosystem** — npm only in the current version
- **Not LLM-generated** — verdicts and briefings are deterministic, code-driven

---

## Future plans

**App-context exploitability (v0.2)** — an optional structured input describing your application's characteristics (routes, parsers, trust boundaries) so findings can be filtered by whether the vulnerable code path is plausibly reachable, not just whether the dependency is present. Planned to include VEX export.

**Multi-ecosystem** — PyPI, Maven, Go modules. No timeline.

These are directions, not commitments.

---

## Building from source

```bash
git clone https://github.com/falc0n-researcher/depfuse-oss.git
cd depfuse-oss
make build     # → bin/depfuse
make test      # full test suite
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

<div align="center">
MIT License · Go · npm
</div>
