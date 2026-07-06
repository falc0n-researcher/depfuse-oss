---
title: Lockfile coverage
layout: default
nav_order: 8
permalink: /lockfiles/
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

* **yarn / pnpm / bun** — flat paths, no full install chains. Transitive packages resolved this way are marked `pathConfidence: low` (vs `exact` for npm) and shown with an `(unranked)` note wherever a dependency chain renders, so a bare package name is never mistaken for a verified root dependency.
* **Peer dependencies** — detected and counted, but not resolved against OSV; surfaced as a coverage note, not silently dropped
* **Private registries** — Depfuse only queries `registry.npmjs.org`. Packages it can't resolve there (private-registry scoped packages, auth-required registries, not-found, offline mode, or a network error) are **never silently skipped**: they're listed in an "Unresolved Dependencies" section (CLI, HTML, and the `unresolved` JSON array) with the specific reason, and any unresolved dependency marks the scan **SCAN INCOMPLETE** (exit code 1) — the same as having no lockfile at all.

Always commit a lockfile for reproducible, complete scans.
