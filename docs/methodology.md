---
title: Methodology
layout: default
nav_order: 5
permalink: /methodology/
---

Depfuse implements a **deterministic exploit-evidence pipeline**. Every verdict is code-driven — no LLM classification, no CVSS-weighted risk scores.

## Pipeline stages

### 1. Resolve

Enumerate npm packages from lockfiles or (fallback) manifest + registry tree. Each component carries name, exact version, scope (production vs dev), and dependency path.

### 2. Match

For each resolved `npm/name@version`, query OSV online or from the offline index. Unresolved components are skipped.

### 3. Classify

Map intelligence artifacts to tiers **P0–P4**. Key invariant: **unverified PoC cannot exceed P2** unless corroborated by KEV, Nuclei, or Metasploit.

### 4. Verdict

| Priority | Production scope | Dev scope |
|----------|------------------|-----------|
| P0 | FIX NOW | OK |
| P1 | FIX NOW | FIX SOON |
| P2 | FIX SOON | FIX SOON |
| P3 / P4 | OK | OK |

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

* VulnCheck XDB is cited but does not currently elevate tier
* GitHub PoC "verified" uses a stars ≥ 10 heuristic
* EPSS P3 does not produce FIX SOON in scan mode
