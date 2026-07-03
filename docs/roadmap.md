---
title: Roadmap
layout: default
nav_order: 12
permalink: /roadmap/
hero: /assets/images/hero-roadmap.png
---

<p class="lead">Directions for Depfuse development — not commitments. npm exploit-evidence classification comes first; multi-ecosystem and app-context reachability follow.</p>

<div class="card-grid">
  <div class="doc-card"><strong>v0.2</strong> App-context exploitability filtering and VEX export.</div>
  <div class="doc-card"><strong>Multi-ecosystem</strong> PyPI, Maven, and Go modules planned.</div>
  <div class="doc-card"><strong>Methodology</strong> XDB tier wiring, full yarn/pnpm graphs.</div>
</div>

## v0.2 — App-context exploitability

Optional structured input for routes, parsers, and trust boundaries. Filter findings by plausible reachability. VEX export planned.

## Multi-ecosystem

PyPI, Maven, and Go modules — planned, no timeline. npm maturity comes first.

## Methodology improvements (under consideration)

* Wire VulnCheck XDB into tier computation
* Surface offline index completeness in scan output
* Full dependency graphs for yarn/pnpm/bun lockfiles
* Peer dependency resolution
* Stricter PoC verification

## Contributing

See [CONTRIBUTING.md](https://github.com/falc0n-researcher/depfuse-oss/blob/main/CONTRIBUTING.md). Classification changes require invariant tests in `internal/classify/classify_test.go`.
