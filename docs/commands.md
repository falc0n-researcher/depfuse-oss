---
title: Commands
layout: default
nav_order: 4
permalink: /commands/
---

## Primary commands

| Command | What it does |
|---------|--------------|
| `depfuse scan [path\|url]` | Scan a project directory or GitHub URL |
| `depfuse package name[@version]` | CVE lookup for a specific npm package |
| `depfuse cve CVE-YYYY-NNNNN` | Exploit-evidence classification for a specific CVE |

## `depfuse scan`

```bash
depfuse scan .
depfuse scan . --tree
depfuse scan . --format json
depfuse scan . --format sarif
depfuse scan . --format html --out-dir ./reports
depfuse scan . --ci --fail-on P0,P1,P2
```

See [Run a scan](run-a-scan/) for detailed usage.

## `depfuse package`

```bash
depfuse package next@15.1.0
depfuse package lodash@4.17.20 --verbose
depfuse package next@15.1.0 --format html --out-dir ./reports
```

## `depfuse cve`

Classifies a CVE by public exploit evidence. Advisory-only verdicts: **PATCH NOW**, **PATCH SOON**, **WATCH**.

```bash
depfuse cve CVE-2025-29927
depfuse cve CVE-2025-29927 --timeline
depfuse cve CVE-2025-29927 --format json
```

> **Note**  
> The `cve` command uses scope-free advisory verdicts. The `scan` command applies production/dev scope for FIX NOW / FIX SOON / OK. See [Evidence levels](evidence-levels/#verdicts).

## Supporting commands

| Command | What it does |
|---------|--------------|
| `depfuse collect` | Build `~/.depfuse/intel.db` from all intelligence feeds |
| `depfuse watch [path]` | Surface prior accepted-risk decisions whose evidence changed |
| `depfuse decisions record/list` | Record and manage acceptance decisions |
| `depfuse doctor` | Validate local setup and intel database age |

## Output formats

| Format | Use case |
|--------|----------|
| `cli` (default) | Terminal output with color and tables |
| `json` | Structured output for automation |
| `html` | Single-page report with dependency tree and evidence table |
| `sarif` | SARIF-compatible tooling integration |

Use `--out-dir <path>` to write HTML and Markdown reports to a directory.

## `depfuse watch` and decisions

```bash
depfuse decisions record CVE-2019-11358 \
  --as accept \
  --reason "jquery only in internal admin, not exposed" \
  --package jquery --version 3.2.1

depfuse watch .
```

See [Decision memory](decision-memory/).
