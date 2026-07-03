---
title: Introduction
layout: default
nav_order: 1
permalink: /
---

**Depfuse** is an open-source CLI that scans npm dependency exposure and classifies CVE matches by **public exploit evidence**. Instead of sorted vulnerability lists with risk scores, it produces **FIX NOW / FIX SOON / OK** verdicts with cited evidence receipts.

## Who is this for?

* Application security and product security teams who want actionable dependency findings, not another CVE dashboard.
* Developers and platform engineers integrating dependency checks into CI without drowning in noise.
* Security researchers validating whether a CVE has real-world exploit tooling behind it.

## Skip the docs, get running fast

Install and scan in two commands — see [Installation](installation/) and [Run a scan](run-a-scan/).

```bash
go install github.com/falc0n-researcher/depfuse-oss/cmd/depfuse@latest
depfuse scan .
```

## What Depfuse answers

| Question | How |
|----------|-----|
| What can an attacker see? | Exact package versions pinned in your lockfile |
| What has public exploit evidence? | KEV, Nuclei, Metasploit, Exploit-DB, PoC metadata, EPSS |
| Which prior decisions need revisiting? | Accepted-risk findings whose exploit picture changed |

## What Depfuse does not do

> **Warning — Scope boundary**  
> Depfuse does **not** assess whether a CVE is reachable in your application's routes and code paths. It classifies **dependency exposure** by the strength of public exploit signals. App-context exploitability is planned for v0.2.

Depfuse is also:

* **Not a CVE risk scorer** — Grype and Trivy produce CVSS+EPSS weighted lists; Depfuse is a different tool for a different workflow.
* **Not multi-ecosystem** — npm only in the current version.
* **Not LLM-generated** — verdicts and briefings are deterministic, code-driven.

## Tool workflow

1. **Resolve** — Walk `package.json` and lockfiles to enumerate pinned npm packages (production vs dev scope).
2. **Match** — Query the OSV advisory database (online batch API or offline index) for each `name@version`.
3. **Classify** — Map intelligence feed artifacts to exploit-evidence tiers **P0–P4**.
4. **Verdict** — Apply scope-aware rules: **FIX NOW**, **FIX SOON**, or **OK**.
5. **Report** — Emit findings with cited evidence receipts and optional upgrade rollup.

## Ecosystem support

| Ecosystem | Current support |
|-----------|-----------------|
| npm | Fully supported |
| PyPI | Planned |
| Maven | Planned |
| Go modules | Planned |

## Sample output

[View sample HTML scan report](https://github.com/falc0n-researcher/depfuse-oss/blob/main/samples/scan.html)

```
  Summary
  ┌─────────────┬─────────┬──────────┬────┬─────────┐
  │ Exploitable │ Fix Now │ Fix Soon │ OK │  Total  │
  ├─────────────┼─────────┼──────────┼────┼─────────┤
  │           1 │       1 │        1 │ 21 │      23 │
  └─────────────┴─────────┴──────────┴────┴─────────┘

  FIX NOW because:
    • [KEV] Listed in VulnCheck KEV catalog
    • [Nuc] Nuclei scanner template exists
    • [Exposure] package-lock.json pins next@15.1.0 (production)
```
