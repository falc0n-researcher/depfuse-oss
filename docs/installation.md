---
title: Installation
layout: default
nav_order: 2
permalink: /installation/
---

## Requirements

* **Go 1.25+** (for building from source)
* **Git** (optional — only needed for remote GitHub repo scans and Nuclei feed collection)

## Install the binary

**go install:**

```bash
go install github.com/falc0n-researcher/depfuse-oss/cmd/depfuse@latest
```

**Build from source:**

```bash
git clone https://github.com/falc0n-researcher/depfuse-oss.git
cd depfuse-oss
make build    # → bin/depfuse
```

## First run

The binary ships with an **embedded weaponized-only advisory snapshot** so a first scan works without network access. For complete OSV coverage and fresh feed data, run collect:

```bash
depfuse collect
```

Collect requires a free [VulnCheck Community](https://vulncheck.com/kev) token:

```bash
export DEPFUSE_VULNCHECK_TOKEN=your_token_here
depfuse collect
```

This builds `~/.depfuse/intel.db` from KEV, EPSS, Nuclei, Metasploit, Exploit-DB, PoC GitHub metadata, and the full OSV npm export.

> **Note — Embedded vs full index**  
> The embedded snapshot covers only advisories Depfuse would **not** classify as quiet (P4) — weaponized CVEs only. Hygiene CVEs without exploit signals are invisible until you run `depfuse collect`. See [Limitations](limitations/#offline-and-embedded-snapshot).

## Validate setup

```bash
depfuse doctor
```

Doctor checks the intel database path, age, and feed snapshot metadata.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `DEPFUSE_VULNCHECK_TOKEN` | VulnCheck Community API token for `collect` |
| `DEPFUSE_INTEL_DB` | Override default `~/.depfuse/intel.db` path |
| `DEPFUSE_SKIP_AUTO_COLLECT` | Set to `1` to disable automatic 4-hour refresh |
| `DEPFUSE_OFFLINE` | Set to `1` to disable all network access |
| `DEPFUSE_COLLECT_TTL` | Auto-refresh interval in hours (default: 4) |
| `DEPFUSE_NO_COLOR` | Disable terminal color output |

## Offline use

```bash
depfuse collect
cp ~/.depfuse/intel.db ./intel.db

export DEPFUSE_INTEL_DB=./intel.db
export DEPFUSE_SKIP_AUTO_COLLECT=1
depfuse scan .
```
