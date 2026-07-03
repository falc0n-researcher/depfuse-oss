---
title: Limitations
layout: default
nav_order: 9
permalink: /limitations/
hero: /assets/images/hero-limitations.png
---

<p class="lead">Depfuse is explicit about what it does and does not claim. Understanding these boundaries helps you interpret scan results correctly and avoid false confidence.</p>

<div class="card-grid">
  <div class="doc-card"><strong>Not reachability</strong> Classifies dependency exposure, not app code paths.</div>
  <div class="doc-card"><strong>Embedded snapshot</strong> Offline scans miss P4 hygiene CVEs until collect.</div>
  <div class="doc-card"><strong>Known gaps</strong> XDB tier wiring, flat yarn/pnpm paths, peer deps.</div>
</div>

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
