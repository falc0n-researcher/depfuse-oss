---
title: Decision memory
layout: default
nav_order: 11
permalink: /decision-memory/
---

<p class="lead">Record accepted-risk findings and get alerted when exploit evidence changes. Decisions suppress repeat noise until reopen conditions fire — keeping your backlog honest over time.</p>

<div class="card-grid">
  <div class="doc-card"><strong>Record</strong> Document why a finding was accepted with context.</div>
  <div class="doc-card"><strong>Watch</strong> Surface decisions when KEV, tier, or EPSS changes.</div>
  <div class="doc-card"><strong>Reopen</strong> Automatic triggers at EPSS ≥ 0.90 or tier escalation.</div>
</div>

## Recording decisions

```bash
depfuse decisions record CVE-2019-11358 \
  --as accept \
  --reason "jquery only in internal admin, not exposed" \
  --package jquery --version 3.2.1
```

## Watch for changes

```bash
depfuse watch .
```

## Explain a decision

`depfuse decisions explain <CVE>` shows a stored decision's full history: what was decided and why, the evidence tier at decision time vs. the current re-classified tier, and whether it would reopen right now.

```bash
depfuse decisions explain CVE-2019-11358
```

```
  CVE-2019-11358

  Scope            jquery@3.2.1
  Decision         accepted-risk
  Reason           jquery only in internal admin, not exposed
  Decided at       2026-01-15
  Level then       P4
  Level now        P2
  Reopens: level changed P4 → P2
```

## Reopen conditions

| Trigger | Example |
|---------|---------|
| CVE added to KEV | New active exploitation |
| Evidence tier escalates | P3 → P1 |
| EPSS crosses 0.90 | High exploitation probability |
| Quiet → Watch | Advisory gains EPSS ≥ 0.05 |

The reopen threshold (0.90) is separate from the P3 classification threshold (0.05).

## What decisions are not

* Not a substitute for VEX (planned v2)
* Not synced across team members by default
* Not permanent — reopen conditions enforce revisiting when evidence escalates
