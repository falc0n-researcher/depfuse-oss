---
title: CI integration
layout: default
nav_order: 10
permalink: /ci/
---

## Basic CI scan

```bash
depfuse scan . --ci --fail-on P0,P1
```

| Flag | Behavior |
|------|----------|
| `--ci` | Pipeline-friendly output |
| `--fail-on` | Tiers that fail the job (default: P0,P1) |

Exit **1** on failing findings or incomplete coverage (no lockfile).

## GitHub Actions example

```yaml
name: depfuse

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Depfuse
        run: go install github.com/falc0n-researcher/depfuse-oss/cmd/depfuse@latest

      - name: Collect intelligence
        env:
          DEPFUSE_VULNCHECK_TOKEN: ${{ secrets.VULNCHECK_TOKEN }}
        run: depfuse collect

      - name: Scan dependencies
        run: depfuse scan . --ci --fail-on P0,P1 --format sarif --out-dir ./sarif
```

## Fail tier recommendations

| Profile | `--fail-on` |
|---------|-------------|
| Strict production | `P0,P1` |
| Paranoid | `P0,P1,P2` |
| Advisory only | `P0` |

P3/P4 never fail CI by default.

## Pinned intel database

```bash
export DEPFUSE_INTEL_DB=./intel.db
export DEPFUSE_SKIP_AUTO_COLLECT=1
depfuse scan . --ci
```

Cache `~/.depfuse/intel.db` between CI runs to avoid full re-collection on every PR.
