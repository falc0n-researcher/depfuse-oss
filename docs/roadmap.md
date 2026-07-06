---
title: Roadmap
layout: default
nav_order: 12
permalink: /roadmap/
hero: /assets/images/hero-roadmap.png
---

<p class="lead">Directions for Depfuse development — not commitments. npm exploit-evidence classification comes first; multi-ecosystem and app-context reachability follow.</p>

<div class="card-grid">
  <div class="doc-card"><strong>v2</strong> App-context exploitability filtering and VEX export.</div>
  <div class="doc-card"><strong>Multi-ecosystem</strong> PyPI, Maven, and Go modules planned.</div>
  <div class="doc-card"><strong>Methodology</strong> XDB tier wiring, full yarn/pnpm graphs.</div>
</div>

## v2 — App-context exploitability

Optional structured input for routes, parsers, and trust boundaries. Filter findings by plausible reachability. VEX export planned.

## Multi-ecosystem

PyPI, Maven, and Go modules — planned, no timeline. npm maturity comes first.

## Recently shipped

* Coverage banner surfaces lockfile/registry-tree/OSV-index completeness on every scan (`meta.coverage`, incl. `snapshotMode` for embedded-vs-online indexes)
* Unresolved dependencies are itemized with a reason (private-registry, auth-required, not-found, network-error, offline-mode) instead of silently skipped
* P3 renders as **WATCH**, not folded into OK
* GitHub PoC "verified" requires ≥2 corroborating signals instead of a stars-alone heuristic; forks never qualify
* `pathConfidence` (`exact`/`low`) flags whether a dependency chain is a verified parent path (npm) or a flat, unranked list (yarn/pnpm/bun); pnpm lockfileVersion 9 (no leading-slash package keys) now parses correctly
* `depfuse decisions explain <CVE>` shows a stored decision's evidence-then-vs-now and reopen status
* `depfuse doctor --ci` lints `.github/workflows/*.yml` for unpinned actions, `pull_request_target`, missing/broad permissions, and npm-publish-without-OIDC
* Install-time lifecycle scripts (preinstall/install/postinstall/prepare) surface as non-scoring supply-chain context

## Methodology improvements (under consideration)

* Wire VulnCheck XDB into tier computation — still citation-only by design; open question, not just an oversight
* Full dependency graphs for yarn/pnpm/bun lockfiles (currently flat, marked `pathConfidence: low`)
* Peer dependency resolution against OSV (currently counted/surfaced, not matched)

## Contributing

See [CONTRIBUTING.md](https://github.com/falc0n-researcher/depfuse-oss/blob/main/CONTRIBUTING.md). Classification changes require invariant tests in `internal/classify/classify_test.go`.
