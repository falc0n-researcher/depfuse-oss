---
title: Methodology
layout: default
nav_order: 5
permalink: /methodology/
---

<p class="lead">Depfuse implements a <strong>deterministic exploit-evidence pipeline</strong>. Every verdict is code-driven — no LLM classification, no CVSS-weighted risk scores.</p>

<div class="card-grid">
  <div class="doc-card"><strong>Resolve → Match</strong> Enumerate pinned deps, query OSV for each version.</div>
  <div class="doc-card"><strong>Classify → Verdict</strong> Map feeds to P0–P4, apply scope-aware rules.</div>
  <div class="doc-card"><strong>Filter → Emit</strong> Honor ignore files and decisions, output receipts.</div>
</div>

## Pipeline stages

### 1. Resolve

Enumerate npm packages from lockfiles or (fallback) manifest + registry tree. Each component carries name, exact version, scope (production vs dev), and dependency path.

### 2. Match

For each resolved `npm/name@version`, query OSV online or from the offline index. Components that can't be resolved to a concrete version (private registry, auth required, not found, network error, or offline mode) are excluded from matching, but never silently dropped — they're itemized with a reason in the "Unresolved Dependencies" output and mark the scan `SCAN INCOMPLETE`.

### 3. Classify

Map intelligence artifacts to tiers **P0–P4**. Key invariant: **unverified PoC cannot exceed P2** unless corroborated by KEV, Nuclei, or Metasploit.

### 4. Verdict

| Priority | Production scope | Dev scope |
|----------|------------------|-----------|
| P0 | <span class="badge badge-fixnow">Fix now</span> | <span class="badge badge-ok">OK</span> |
| P1 | <span class="badge badge-fixnow">Fix now</span> | <span class="badge badge-fixsoon">Fix soon</span> |
| P2 | <span class="badge badge-fixsoon">Fix soon</span> | <span class="badge badge-fixsoon">Fix soon</span> |
| P3 | <span class="badge badge-watch">Watch</span> | <span class="badge badge-watch">Watch</span> |
| P4 | <span class="badge badge-ok">OK</span> | <span class="badge badge-ok">OK</span> |

WATCH never fails CI by default (add it explicitly with `--fail-on P0,P1,watch`) — it exists so a P3 finding is visible as "no known exploit yet, but worth watching," not indistinguishable from P4 hygiene noise.

### 5. Filter

`.depfuseignore` and recorded decisions suppress findings until reopen conditions fire.

### 6. Emit

CLI, JSON, HTML, or SARIF with evidence receipts and optional upgrade rollup.

## Design principles

**Evidence, not exploitability** — Depfuse answers whether public exploit tooling exists and the package is pinned in your tree. It does not determine code reachability in your application.

**Honest coverage** — No lockfile → SCAN INCOMPLETE (exit 1). Embedded snapshot → weaponized CVEs only.

**No CVSS as exploit signal** — EPSS is used only as a watch signal (P3) at threshold ≥ 0.05.

## Classification decision tree

```
KEV present?                          → P0
Nuclei OR Metasploit OR verified PoC? → P1
Exploit-DB OR unverified PoC?         → P2 (cap enforced)
EPSS ≥ 0.05?                          → P3
Otherwise                             → P4 (hygiene)
```

## Known methodology gaps

See [Limitations](limitations/). Highlights:

* VulnCheck XDB is cited but does not currently elevate tier — every citation says so explicitly
* GitHub PoC "verified" requires ≥2 corroborating signals, not stars alone; forks never qualify
* Yarn/pnpm/bun dependency paths are flat (`pathConfidence: low`), unlike npm's full graph
