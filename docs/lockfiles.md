---
title: Lockfile coverage
layout: default
nav_order: 8
permalink: /lockfiles/
hero: /assets/images/hero-scan.png
---

<p class="lead">Depfuse resolves exact pinned versions from lockfiles to build an accurate dependency graph. Without a lockfile, scans are marked <strong>SCAN INCOMPLETE</strong> — transitive coverage cannot be guaranteed.</p>

<div class="card-grid">
  <div class="doc-card"><strong>npm lock v2/v3</strong> Full dependency graph with install paths.</div>
  <div class="doc-card"><strong>yarn / pnpm / bun</strong> Supported with flat path resolution.</div>
  <div class="doc-card"><strong>Always commit</strong> A lockfile is required for reproducible, complete scans.</div>
</div>

## Supported lockfiles

| Lockfile | Support | Dependency paths |
|----------|---------|------------------|
| `package-lock.json` v2/v3 | Full | Full graph |
| `package-lock.json` v1 | Supported | `dependencies` tree |
| `yarn.lock` v1 + Berry | Supported | Flat (name only) |
| `pnpm-lock.yaml` | Supported | Flat (name only) |
| `bun.lock` | Supported | Flat (name only) |
| `bun.lockb` | **Not supported** | — |
| `npm-shrinkwrap.json` | Supported | Same as package-lock |

## Coverage levels

| Level | Condition | Exit code |
|-------|-----------|-----------|
| **Complete** | Lockfile found, deps pinned | 0 |
| **Partial** | Registry tree expanded transitivity | 0 |
| **Incomplete** | Manifest-only, no lockfile | **1** |

> **Warning**  
> Registry-tree resolution may not match your actual install graph. Treat partial scans as indicative.

## Known limitations

* **yarn / pnpm / bun** — flat paths, no full install chains
* **Peer dependencies** — not resolved or scanned
* **Private registries** — only `registry.npmjs.org`; unresolved packages are skipped silently

Always commit a lockfile for reproducible, complete scans.
