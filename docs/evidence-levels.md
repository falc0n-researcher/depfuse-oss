---
title: Evidence levels
layout: default
nav_order: 6
permalink: /evidence-levels/
---

<p class="lead">Depfuse maps public exploit signals to a five-tier priority ladder (<strong>P0–P4</strong>), then applies scope-aware verdict rules. CVSS is never used as an exploit signal.</p>

<div class="card-grid">
  <div class="doc-card"><strong>P0–P2</strong> Active exploitation through available exploit tooling.</div>
  <div class="doc-card"><strong>P3</strong> OSV match with elevated EPSS, no exploit signal.</div>
  <div class="doc-card"><strong>P4</strong> Hygiene — advisory exists, no public exploit evidence.</div>
</div>

## Priority ladder

| Level | Label | Signal |
|-------|-------|--------|
| **P0** | Actively Exploited | VulnCheck KEV |
| **P1** | Weaponized | Nuclei template · Metasploit module · verified PoC |
| **P2** | Exploit Available | Exploit-DB entry · unverified PoC |
| **P3** | Low Exploitability | OSV match + EPSS ≥ 0.05, no exploit signal |
| **P4** | Hygiene | OSV match, no exploit signal, low or no EPSS |

**Invariant:** Unverified PoC cannot exceed P2. CVSS is not used as an exploit signal.

## Verdicts

### Scan mode (`depfuse scan`, `depfuse package`)

| Verdict | Condition |
|---------|-----------|
| **FIX NOW** | P0 or P1 in **production** dependencies |
| **FIX SOON** | P2 in any scope; P1 in **dev-only** dependencies |
| **WATCH** | P3 (any scope) |
| **OK** | P4; or P0/P1 scoped to dev-only dependencies |

> **Note**  
> WATCH never fails CI by default — add it explicitly with `--fail-on P0,P1,watch`. It exists so a P3 finding stays visible as "no known exploit yet, worth watching" instead of disappearing into P4 hygiene noise.

### CVE mode (`depfuse cve`)

| Verdict | Condition |
|---------|-----------|
| **PATCH NOW** | P0 or P1 |
| **PATCH SOON** | P2 |
| **WATCH** | P3 or P4 |

## Receipt tags

| Tag | Source |
|-----|--------|
| `[KEV]` | VulnCheck Known Exploited Vulnerabilities |
| `[Nuc]` | Nuclei scanner template |
| `[MSF]` | Metasploit framework module |
| `[EDB]` | Exploit-DB entry |
| `[PoC]` | Public PoC repository (metadata only) |
| `[EPSS]` | FIRST EPSS score |
| `[Exposure]` | Lockfile pin + scope + dependency path |

## EPSS thresholds

| Threshold | Used for |
|-----------|----------|
| ≥ 0.05 | P3 classification (watch band) |
| ≥ 0.90 | Decision reopen trigger |
