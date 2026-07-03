---
title: Roadmap
layout: default
nav_order: 12
permalink: /roadmap/
---

Directions, not commitments.

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
