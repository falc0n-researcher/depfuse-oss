---
title: Limitations
layout: default
nav_order: 9
permalink: /limitations/
---

Depfuse is explicit about what it does and does not claim.

## Scope boundaries

| Depfuse does | Depfuse does not |
|--------------|------------------|
| Match pinned deps to OSV advisories | Determine code reachability |
| Classify by public exploit evidence | Score risk using CVSS |
| Produce FIX NOW / FIX SOON / OK | Replace SAST/DAST |
| Cite evidence receipts | Download or run exploit code |

## Critical gaps

### Offline and embedded snapshot

The binary embeds a **weaponized-only** snapshot. Quiet hygiene CVEs (P4) are missed until `depfuse collect` builds the full OSV index.

> **Warning**  
> A clean offline first scan means zero *weaponized* CVEs in the embedded index — not zero CVEs overall.

### VulnCheck XDB

XDB artifacts are cited but **do not elevate priority tier** today.

### Flat lockfile parsing

Yarn, pnpm, and bun lockfiles produce flat dependency paths — weaker transitive exposure analysis than npm lockfile v2/v3.

## Medium gaps

* PoC GitHub search limited to CVEs already in weaponization feeds
* GitHub PoC "verified" = stars ≥ 10 (weak heuristic)
* Registry-tree partial coverage without lockfile
* Unresolved packages silently skipped from OSV matching
* Peer dependencies not scanned
* P3 (EPSS ≥ 0.05) → OK in scan mode, not FIX SOON

## Reporting gaps

[Open an issue](https://github.com/falc0n-researcher/depfuse-oss/issues) with CVE ID, expected tier, and evidence source.
