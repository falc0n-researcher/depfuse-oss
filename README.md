<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/depfuse-banner.png">
  <img src="assets/depfuse-banner.png" alt="Depfuse — exploit-evidence decisions for npm dependencies" width="100%">
</picture>

<div align="center">

**Stop sorting CVE lists. Start acting on exploit evidence.**

[![License: MIT](https://img.shields.io/badge/License-MIT-FF6B2C?style=flat-square)](LICENSE)
[![Go 1.25+](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-FF6B2C?style=flat-square)](https://falc0n-researcher.github.io/depfuse-oss/)

[Install](#install) · [Quick start](#quick-start) · [Documentation](https://falc0n-researcher.github.io/depfuse-oss/) · [Sample report](samples/scan.html)

</div>

---

**Depfuse** scans your npm lockfile, matches OSV advisories, and returns **FIX NOW · FIX SOON · OK** — with cited receipts from KEV, Nuclei, Metasploit, Exploit-DB, and more. No CVSS roulette. No LLM guesses. Deterministic, evidence-driven.

> Depfuse classifies **dependency exposure + public exploit signals**. It does not do reachability analysis (yet). [Read the scope →](https://falc0n-researcher.github.io/depfuse-oss/limitations/)

## Install

```bash
go install github.com/falc0n-researcher/depfuse-oss/cmd/depfuse@latest
```

Works offline on first run. Run `depfuse collect` for the full OSV index and fresh feeds.

## Quick start

```bash
depfuse scan .                          # local project
depfuse scan . --ci --fail-on P0,P1     # gate CI on active exploitation
depfuse cve CVE-2025-29927              # classify a CVE without a lockfile
```

<details>
<summary><strong>Sample output</strong></summary>

```
  Summary
  ┌─────────────┬─────────┬──────────┬────┬─────────┐
  │ Exploitable │ Fix Now │ Fix Soon │ OK │  Total  │
  ├─────────────┼─────────┼──────────┼────┼─────────┤
  │           1 │       1 │        1 │ 21 │      23 │
  └─────────────┴─────────┴──────────┴────┴─────────┘

  │ P0 · Exploited    │ CVE-2025-29927 │ next@15.1.0   │ KEV Nuc  │ FIX NOW  │
  │ P2 · Exploit Avail │ CVE-2019-11358 │ jquery@3.2.1  │ EDB      │ FIX SOON │

  FIX NOW because:
    • [KEV] Listed in VulnCheck KEV catalog
    • [Nuc] Nuclei scanner template exists
    • [Exposure] package-lock.json pins next@15.1.0 (production)
```

→ [Full HTML report](samples/scan.html)

</details>

## How it thinks

```
  Lockfile          OSV match         Exploit feeds        Verdict
  ─────────  ───►  ─────────  ───►  ─────────────  ───►  FIX NOW
  name@version      CVE-2025-…        KEV · Nuclei         FIX SOON
                                      Metasploit · EDB     OK
                                      PoC · EPSS
```

| Question | Depfuse answer |
|----------|----------------|
| What's pinned in prod? | Exact versions from your lockfile |
| Is there real exploit evidence? | P0–P4 tier from public feeds |
| Did a prior acceptance go stale? | `depfuse watch` reopens on KEV / tier change |

### Evidence → verdict

| Level | Signal | Scan verdict (prod) |
|-------|--------|-------------------|
| **P0** | VulnCheck KEV | **FIX NOW** |
| **P1** | Nuclei · Metasploit · verified PoC | **FIX NOW** |
| **P2** | Exploit-DB · unverified PoC | **FIX SOON** |
| **P3/P4** | OSV only · low EPSS | **OK** |

Every actionable finding ships **evidence receipts** — `[KEV]` `[Nuc]` `[MSF]` `[EDB]` `[PoC]` `[EPSS]` `[Exposure]`. [Full methodology →](https://falc0n-researcher.github.io/depfuse-oss/methodology/)

## Commands

| Command | One line |
|---------|----------|
| `depfuse scan [path\|url]` | Scan lockfile + classify all CVE matches |
| `depfuse package name@version` | Lookup a single package from the registry |
| `depfuse cve CVE-YYYY-NNNNN` | Classify exploit evidence for one CVE |
| `depfuse collect` | Refresh intel.db from all feeds |
| `depfuse watch` | Surface accepted-risk decisions that need revisiting |

**Lockfiles:** `package-lock.json` · `yarn.lock` · `pnpm-lock.yaml` · `bun.lock` · workspaces  
**Formats:** CLI · JSON · HTML · SARIF

→ [All commands & flags](https://falc0n-researcher.github.io/depfuse-oss/commands/) · [CI integration](https://falc0n-researcher.github.io/depfuse-oss/ci/)

## Not another scanner

| | Grype / Trivy | Depfuse |
|---|---------------|---------|
| Output | Sorted CVE list + CVSS | **FIX NOW / FIX SOON / OK** |
| Signal | Severity scores | **Public exploit evidence** |
| Verdicts | You decide | **Cited receipts per finding** |
| Reachability | Varies | **Not yet** (v0.2 planned) |

## Build from source

```bash
git clone https://github.com/falc0n-researcher/depfuse-oss.git && cd depfuse-oss
make build && make test
```

## Contributing

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Classification changes need invariant tests in `internal/classify/`.

---

<div align="center">

**[Documentation](https://falc0n-researcher.github.io/depfuse-oss/)** · MIT License · npm · Go

</div>
