---
title: Evidence levels
layout: default
nav_order: 6
permalink: /evidence-levels/
---

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
| **OK** | P3/P4; or P0/P1 scoped to dev-only dependencies |

> **Note**  
> P3 maps to **OK** in scan mode, not FIX SOON. Use `depfuse cve` for advisory-only WATCH verdicts.

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
