---
title: Run a scan
layout: default
nav_order: 3
permalink: /run-a-scan/
hero: /assets/images/hero-scan.png
---

<p class="lead">Point Depfuse at a local project directory or GitHub URL. It walks lockfiles, matches pinned versions against OSV, and returns verdicts with evidence receipts — in the terminal, JSON, SARIF, or HTML.</p>

<div class="card-grid">
  <div class="doc-card"><strong>Local or remote</strong> Scan <code>.</code>, a path, or a GitHub repo URL.</div>
  <div class="doc-card"><strong>Multiple formats</strong> CLI, JSON, SARIF, and HTML report output.</div>
  <div class="doc-card"><strong>CI-ready</strong> Use <code>--ci --fail-on P0,P1</code> to gate pipelines.</div>
</div>

## Local project

```bash
depfuse scan .
depfuse scan /path/to/project
```

Depfuse discovers lockfiles by walking up from the scan root. Supported lockfiles are listed on the [Lockfile coverage](lockfiles/) page.

## Remote GitHub repository

```bash
depfuse scan https://github.com/org/repo
```

The repository is cloned to a temporary directory, scanned, and cleaned up.

## Common flags

```bash
# Expand the lockfile dependency tree at the end of CLI output (scan only)
depfuse scan . --tree

# Output formats
depfuse scan . --format json
depfuse scan . --format sarif
depfuse scan . --format html

# Write HTML and Markdown reports to a directory
depfuse scan . --out-dir ./reports

# CI mode — suppress interactive output, explicit fail condition
depfuse scan . --ci --fail-on P0,P1
```

> **Note — Nested dependencies**  
> `depfuse scan` resolves your lockfile graph; use `--tree` to print it expanded. For a single package lookup with registry transitivity, use [`depfuse package`](commands/#depfuse-package) — nested paths (e.g. `express → qs`) appear in the findings table by default.

## No lockfile?

If no lockfile is found, the scan is marked **SCAN INCOMPLETE** and exits with code **1**. Transitive dependencies cannot be fully covered without a pinned lockfile.

> **Warning**  
> Manifest-only scans resolve direct dependencies and may expand transitivity via the npm registry, but coverage is **partial** — not equivalent to a lockfile-pinned graph.

## Reading the output

### Summary table

| Column | Meaning |
|--------|---------|
| Exploitable | P0–P2 findings (active exploit signals) |
| Fix Now | Production deps requiring immediate action |
| Fix Soon | P2 or P1 in dev-only scope |
| OK | P3/P4 or P0/P1 scoped to dev-only production-safe cases |

### Evidence receipts

Every actionable verdict includes cited reasons:

```
FIX NOW because:
  • [KEV] Listed in VulnCheck KEV catalog
  • [Nuc] Nuclei scanner template exists
  • [EPSS] Score 0.89
  • [Exposure] package-lock.json pins next@15.1.0 (production · direct)
```

Receipt tags: `[KEV]` `[Nuc]` `[MSF]` `[EDB]` `[PoC]` `[EPSS]` `[Exposure]`

## Sample reports

* [Scan report](https://github.com/falc0n-researcher/depfuse-oss/blob/main/samples/scan.html)
* [Package report](https://github.com/falc0n-researcher/depfuse-oss/blob/main/samples/package.html)
* [CVE report](https://github.com/falc0n-researcher/depfuse-oss/blob/main/samples/cve.html)

### Terminal demo

![Package scan demo](/assets/casts/depfuse-package-express.gif)

```bash
depfuse package express@4.17.1 --depth 2
```

Regenerate the GIF with `make demo-gif` (requires [agg](https://github.com/asciinema/agg) and seeded `testdata/intel.db`).

## Next steps

* [Commands](commands/) — `package`, `cve`, `watch`, `decisions`
* [CI integration](ci/) — gate releases on exploit evidence
* [Methodology](methodology/) — how classification works
