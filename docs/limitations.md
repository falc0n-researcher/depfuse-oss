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
  <div class="doc-card"><strong>Embedded snapshot</strong> Coverage banner flags when only the weaponized-only index was used.</div>
  <div class="doc-card"><strong>Known gaps</strong> XDB tier wiring, flat yarn/pnpm/bun paths, peer dep matching.</div>
</div>

## Scope boundaries

| Depfuse does | Depfuse does not |
|--------------|------------------|
| Match pinned deps to OSV advisories | Determine code reachability |
| Classify by public exploit evidence | Score risk using CVSS |
| Produce FIX NOW / FIX SOON / WATCH / OK | Replace SAST/DAST |
| Cite evidence receipts | Download or run exploit code |

## Critical gaps

### Offline and embedded snapshot

The binary embeds a **weaponized-only** snapshot. Quiet hygiene CVEs (P4) are missed until `depfuse collect` builds the full OSV index. Every scan's coverage banner reports which index served it (`meta.coverage.snapshotMode`: `online`, `full-offline-db`, or `embedded-snapshot`), so this is never silent.

> **Warning**  
> A clean offline first scan means zero *weaponized* CVEs in the embedded index — not zero CVEs overall.

### VulnCheck XDB

XDB artifacts are cited but **do not elevate priority tier** today. Every XDB citation says so explicitly ("citation only, does not affect priority tier").

### Flat lockfile parsing

Yarn, pnpm, and bun lockfiles produce flat dependency paths (`pathConfidence: low`) — weaker transitive exposure analysis than npm lockfile v1/v2/v3 (`pathConfidence: exact`). A dependency chain rendered from a flat-resolved package is marked `(unranked)` so it isn't mistaken for a verified parent chain.

## Medium gaps

* PoC GitHub search limited to CVEs already in weaponization feeds
* GitHub PoC "verified" requires ≥2 corroborating signals (exact CVE match in repo name/description, community attention, a real description) — forks are never marked verified regardless of signal count. Still weaker than a validated exploit artifact.
* Registry-tree partial coverage without lockfile
* Peer dependencies are detected and counted (`coverage.peerDependencyCount`) but not resolved against OSV — surfaced as a coverage note, not silently dropped
* Unresolved dependencies (private-registry, auth-required, not-found, network-error, offline-mode) are itemized with a reason in the CLI, HTML, and `unresolved` JSON array — never silently skipped — and mark the scan `SCAN INCOMPLETE`
* Install-time lifecycle scripts (preinstall/install/postinstall/prepare) are surfaced as supply-chain context on the *latest* published version only (not necessarily the exact pinned version) — this never affects priority or verdict

## Reporting gaps

[Open an issue](https://github.com/falc0n-researcher/depfuse-oss/issues) with CVE ID, expected tier, and evidence source.
