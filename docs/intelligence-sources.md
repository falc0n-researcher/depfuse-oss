---
title: Intelligence sources
layout: default
nav_order: 7
permalink: /intelligence-sources/
---

<p class="lead">Depfuse ingests metadata from public exploit-intelligence feeds during <code>depfuse collect</code>. No exploit code or PoC files are downloaded or executed — only classification signals.</p>

<div class="card-grid">
  <div class="doc-card"><strong>Authoritative</strong> VulnCheck KEV drives P0 (actively exploited).</div>
  <div class="doc-card"><strong>Weaponized</strong> Nuclei, Metasploit, and verified PoCs → P1.</div>
  <div class="doc-card"><strong>Watch band</strong> EPSS ≥ 0.05 elevates to P3 when no exploit signal exists.</div>
</div>

## Feed registry

| Feed | Source | Trust | Tier impact |
|------|--------|-------|-------------|
| VulnCheck KEV | [VulnCheck Community KEV API](https://vulncheck.com/kev) | Authoritative | **P0** |
| Nuclei | [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | High | **P1** |
| Metasploit | Rapid7 modules metadata | High | **P1** |
| Exploit-DB | Offensive Security CSV | Medium | **P2** |
| PoC GitHub | GitHub Search API (metadata only) | Low | **P2** or **P1** (verified) |
| EPSS | [FIRST EPSS](https://www.first.org/epss/) | Medium | **P3** (≥ 0.05) |
| OSV advisories | [OSV API](https://osv.dev/) | Advisory baseline | Match source |

## VulnCheck XDB

XDB is ingested during collect and cited in evidence receipts but **does not currently elevate priority tier**. See [Limitations](limitations/#vulncheck-xdb).

## Collection

```bash
export DEPFUSE_VULNCHECK_TOKEN=your_token
depfuse collect
```

Order: KEV → Metasploit → Exploit-DB → Nuclei → PoC GitHub → EPSS → OSV npm export.

Auto-refresh runs every 4 hours unless `DEPFUSE_SKIP_AUTO_COLLECT=1`.

## Offline index

Full OSV index requires `depfuse collect`. The embedded binary snapshot covers weaponized advisories only (KEV, Nuclei, MSF, EDB, PoC, EPSS ≥ 0.05).

## Data storage

SQLite at `~/.depfuse/intel.db` with schema versioning and observed timestamps for reopen logic.
