---
title: CI integration
layout: default
nav_order: 10
permalink: /ci/
hero: /assets/images/hero-ci.png
---

<p class="lead">Gate pull requests and releases on exploit evidence, not CVSS noise. Use <code>--ci --fail-on</code> to fail the pipeline when weaponized CVEs appear in production dependencies.</p>

<div class="card-grid">
  <div class="doc-card"><strong>--ci</strong> Pipeline-friendly output without interactive formatting.</div>
  <div class="doc-card"><strong>--fail-on</strong> Choose which tiers (P0–P2) fail the job.</div>
  <div class="doc-card"><strong>SARIF export</strong> Integrate with GitHub Advanced Security tooling.</div>
</div>

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
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1

      - name: Install Depfuse
        run: go install github.com/falc0n-researcher/depfuse-oss/cmd/depfuse@latest

      - name: Collect intelligence
        env:
          DEPFUSE_VULNCHECK_TOKEN: ${{ secrets.VULNCHECK_TOKEN }}
        run: depfuse collect

      - name: Scan dependencies
        run: depfuse scan . --ci --fail-on P0,P1 --format sarif --out-dir ./sarif
```

> **Note**  
> Third-party actions should always be pinned to a full-length commit SHA (not a tag or branch), so a tag can't be silently moved to point at different — or malicious — code. `depfuse doctor --ci` checks your `.github/workflows/*.yml` for unpinned actions, `pull_request_target`, missing `permissions:`, and npm-publish steps using a long-lived token instead of OIDC trusted publishing.

## Fail tier recommendations

| Profile | `--fail-on` |
|---------|-------------|
| Strict production | `P0,P1` |
| Paranoid | `P0,P1,P2` |
| Advisory only | `P0` |

P3/P4 never fail CI by default. P3 (WATCH) can be added explicitly with `--fail-on P0,P1,watch`.

## Pinned intel database

```bash
export DEPFUSE_INTEL_DB=./intel.db
export DEPFUSE_SKIP_AUTO_COLLECT=1
depfuse scan . --ci
```

Cache `~/.depfuse/intel.db` between CI runs to avoid full re-collection on every PR.
