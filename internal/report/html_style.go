package report

const htmlStyles = `<style>
@import url('https://fonts.googleapis.com/css2?family=Geist+Mono:ital,wght@0,100..900;1,100..900&display=swap');

:root {
  --bg: #f4f6f9;
  --surface: #ffffff;
  --surface-2: #f8fafc;
  --border: #e2e8f0;
  --border-strong: #cbd5e1;
  --text: #0f172a;
  --text-2: #334155;
  --muted: #64748b;
  --accent: #ea580c;
  --accent-soft: #fff7ed;
  --danger: #dc2626;
  --danger-soft: #fef2f2;
  --warn: #d97706;
  --warn-soft: #fffbeb;
  --ok: #059669;
  --ok-soft: #ecfdf5;
  --info: #0284c7;
  --poc: #7c3aed;
  --font: 'Geist Mono', ui-monospace, monospace;
  --radius: 12px;
  --shadow: 0 1px 3px rgba(15,23,42,.06), 0 4px 16px rgba(15,23,42,.04);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font);
  font-size: 13px;
  line-height: 1.55;
  background: #e8ecf1;
  color: var(--text);
  -webkit-font-smoothing: antialiased;
}

/* ── Dashboard shell (single page) ── */
.dash {
  max-width: 1400px;
  margin: 0 auto;
  padding: 0 1.25rem 3rem;
}
.dash-header {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: flex-end;
  gap: 1rem 2rem;
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
  color: #f1f5f9;
  margin: 0 -1.25rem 1.25rem;
  padding: 1.5rem 1.75rem;
  border-bottom: 3px solid var(--accent);
}
.dash-logo {
  font-size: 1.35rem;
  font-weight: 700;
  letter-spacing: -.02em;
}
.brand-mark { color: var(--accent); margin-right: .35rem; }
.dash-tagline { font-size: .72rem; color: #94a3b8; margin-top: .25rem; }
.dash-header-meta {
  display: flex;
  flex-wrap: wrap;
  gap: .5rem;
  justify-content: flex-end;
}
.meta-chip {
  display: inline-flex;
  flex-direction: column;
  gap: .1rem;
  padding: .4rem .75rem;
  background: rgba(255,255,255,.06);
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 8px;
  font-size: .75rem;
  font-weight: 600;
}
.meta-chip label {
  font-size: .58rem;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: #64748b;
  font-weight: 500;
}
.meta-chip-accent { border-color: rgba(234,88,12,.4); background: rgba(234,88,12,.12); }
.meta-chip-wide { max-width: 28rem; white-space: normal; line-height: 1.35; }

.dash-kpis {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: .65rem;
  margin-bottom: 1.25rem;
}
@media (max-width: 1100px) { .dash-kpis { grid-template-columns: repeat(3, 1fr); } }
@media (max-width: 600px) { .dash-kpis { grid-template-columns: repeat(2, 1fr); } }
.dash-kpi {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: .85rem 1rem;
  box-shadow: var(--shadow);
}
.dash-kpi-value {
  font-size: 1.65rem;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  line-height: 1.1;
}
.dash-kpi-label { font-size: .68rem; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; margin-top: .2rem; }
.dash-kpi-hint { font-size: .6rem; color: var(--muted); margin-top: .15rem; }
.dash-kpi.kpi-danger { border-left: 3px solid var(--danger); }
.dash-kpi.kpi-danger .dash-kpi-value { color: var(--danger); }
.dash-kpi.kpi-alert { border-left: 3px solid var(--accent); }
.dash-kpi.kpi-alert .dash-kpi-value { color: var(--accent); }
.dash-kpi.kpi-warn { border-left: 3px solid var(--warn); }
.dash-kpi.kpi-warn .dash-kpi-value { color: var(--warn); }
.dash-kpi.kpi-ok { border-left: 3px solid var(--ok); }
.dash-kpi.kpi-ok .dash-kpi-value { color: var(--ok); }
.dash-kpi.kpi-muted .dash-kpi-value { color: var(--text-2); }

.dash-row {
  display: grid;
  grid-template-columns: 1.4fr 1fr;
  gap: 1rem;
  margin-bottom: 1rem;
}
@media (max-width: 900px) { .dash-row { grid-template-columns: 1fr; } }

.dash-panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.15rem 1.35rem;
  margin-bottom: 1rem;
  box-shadow: var(--shadow);
}
.dash-panel-full { margin-bottom: 1rem; }
.panel-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: .75rem;
  margin-bottom: 1rem;
  padding-bottom: .65rem;
  border-bottom: 1px solid var(--border);
}
.panel-head h2 {
  font-size: .78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .1em;
  color: var(--text);
}
.panel-count { font-size: .72rem; color: var(--muted); }
.action-cards { display: flex; flex-direction: column; gap: .75rem; max-height: 520px; overflow-y: auto; }

.findings-table { width: 100%; border-collapse: collapse; font-size: .74rem; }
.findings-table th {
  text-align: left;
  padding: .55rem .65rem;
  background: var(--surface-2);
  border-bottom: 2px solid var(--border);
  font-size: .62rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  white-space: nowrap;
}
.findings-table td {
  padding: .5rem .65rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
.findings-table tbody tr:hover { background: var(--surface-2); }
.path-cell { font-size: .68rem; color: var(--muted); max-width: 180px; word-break: break-word; }

.pkg-accord {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: .5rem;
  background: var(--surface);
  overflow: hidden;
}
.pkg-accord-summary {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: .45rem .65rem;
  padding: .75rem 1rem;
  cursor: pointer;
  background: linear-gradient(90deg, var(--surface-2) 0%, var(--surface) 100%);
  list-style: none;
  font-weight: 600;
}
.pkg-accord-summary::-webkit-details-marker { display: none; }
.accord-name { font-size: .85rem; }
.accord-ver { color: var(--muted); font-weight: 500; font-size: .78rem; }
.accord-badge {
  font-size: .62rem;
  padding: .15rem .45rem;
  border-radius: 999px;
  font-weight: 600;
  margin-left: auto;
}
.accord-ok { background: var(--ok-soft); color: var(--ok); }
.accord-shadow { font-size: .65rem; color: var(--muted); font-weight: 400; }
.pkg-accord-body { padding: 1rem 1.15rem; border-top: 1px solid var(--border); }
.pkg-accord-desc { font-size: .78rem; color: var(--text-2); margin-bottom: .75rem; line-height: 1.5; }
.pkg-accord-eco { font-size: .72rem; margin: -.35rem 0 .65rem; line-height: 1.45; }
.pkg-accord-home { font-size: .72rem; margin: -.25rem 0 .65rem; }
.pkg-accord-home a { color: var(--info); text-decoration: none; }
.pkg-accord-home a:hover { text-decoration: underline; }
.pkg-accord-meta {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: .5rem;
  margin-bottom: .75rem;
}
.pkg-accord-tree { margin-top: .75rem; padding-top: .75rem; border-top: 1px dashed var(--border); }

.dash-footer {
  text-align: center;
  font-size: .68rem;
  color: var(--muted);
  padding: 2rem 0 1rem;
  border-top: 1px solid var(--border);
  margin-top: 1rem;
}

.coverage-banner { margin: 0 -1.25rem 1rem; padding: .75rem 1.75rem; }

@media print {
  .dash-header { break-after: avoid; }
  .dash-panel { break-inside: avoid; }
}

.dim { color: var(--muted); }

.panel h2,
.section-head h2,
.receipts-title,
.fix-label {
  text-transform: uppercase;
  letter-spacing: .08em;
}

.cve-link { font-weight: 600; color: var(--info); text-decoration: none; }
.cve-link:hover { text-decoration: underline; }
.link-sm { font-size: .68rem; margin-right: .35rem; }
.pkg-link { font-weight: 600; text-decoration: none; }
.pkg-link:hover { text-decoration: underline; }
.summary-cell { max-width: 220px; font-size: .74rem; color: var(--text-2); }
.cve-catalog th { white-space: nowrap; }

/* ── Package dossier ── */
.pkg-dossier-hero {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
  margin-bottom: 1.25rem;
  padding: 1.25rem 1.5rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}
.pkg-dossier-title h2 {
  font-size: 1.5rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .04em;
}
.pkg-dossier-ver { color: var(--muted); font-size: .9rem; }
.pkg-dossier-home { font-size: .72rem; color: var(--info); word-break: break-all; }
.pkg-dossier-meta {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: .75rem;
  margin-bottom: 1.25rem;
}
.dossier-meta-item {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: .65rem .85rem;
}
.dossier-meta-item label {
  display: block;
  font-size: .58rem;
  color: var(--muted);
  letter-spacing: .08em;
  margin-bottom: .25rem;
}
.dossier-meta-item span { font-size: .78rem; font-weight: 600; color: var(--text); }
.pkg-dossier-desc {
  font-size: .82rem;
  line-height: 1.55;
  color: var(--text-2);
  padding: 1rem 1.15rem;
  background: var(--surface-2);
  border-radius: var(--radius);
  border: 1px solid var(--border);
  margin-bottom: 1.5rem;
}

/* ── Dependency tree ── */
.dep-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(7rem, 1fr));
  gap: .65rem;
  margin-bottom: 1rem;
}
.dep-stat {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: .75rem .85rem;
  text-align: center;
}
.dep-stat-value {
  font-size: 1.35rem;
  font-weight: 700;
  line-height: 1.1;
  color: var(--text);
}
.dep-stat-label {
  font-size: .62rem;
  letter-spacing: .06em;
  color: var(--muted);
  margin-top: .25rem;
}
.dep-toolbar {
  display: flex;
  align-items: center;
  gap: .5rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
}
.dep-toolbar-label {
  font-size: .68rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  margin-right: .15rem;
}
.dep-filter-btn {
  font: inherit;
  font-size: .72rem;
  padding: .35rem .65rem;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text-2);
  cursor: pointer;
}
.dep-filter-btn:hover { border-color: var(--accent); color: var(--text); }
.dep-filter-btn.active {
  background: var(--accent-soft);
  border-color: var(--accent);
  color: var(--accent);
  font-weight: 600;
}
.dep-forest {
  display: flex;
  flex-direction: column;
  gap: .75rem;
}
.dep-forest-compact {
  max-height: 520px;
  overflow-y: auto;
  padding-right: .25rem;
}
.dep-root {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  overflow: hidden;
}
.dep-root[data-dep-has-cve="true"] { border-left: 3px solid var(--danger); }
.dep-root > summary,
.dep-nested > summary { list-style: none; }
.dep-root > summary::-webkit-details-marker,
.dep-nested > summary::-webkit-details-marker { display: none; }
.dep-summary {
  display: flex;
  align-items: center;
  gap: .55rem;
  flex-wrap: wrap;
  padding: .75rem 1rem;
  cursor: pointer;
  background: var(--surface-2);
  border-bottom: 1px solid transparent;
  transition: background .15s;
}
.dep-root[open] > .dep-summary,
.dep-nested[open] > .dep-summary { border-bottom-color: var(--border); }
.dep-summary:hover { background: var(--surface); }
.dep-summary-root { font-weight: 600; }
.dep-summary-cve { background: rgba(239, 68, 68, .06); }
.dep-chevron {
  width: .55rem;
  height: .55rem;
  border-right: 2px solid var(--muted);
  border-bottom: 2px solid var(--muted);
  transform: rotate(-45deg);
  transition: transform .15s;
  flex-shrink: 0;
}
details[open] > .dep-summary .dep-chevron { transform: rotate(45deg); margin-top: -.15rem; }
.dep-root-body { padding: .35rem 0 .65rem; }
.dep-branch {
  list-style: none;
  margin: 0;
  padding: 0 0 0 1.5rem;
  border-left: 2px solid var(--border);
}
.dep-item {
  position: relative;
  padding: .2rem 0 .2rem .85rem;
  font-size: .78rem;
}
.dep-item::before {
  content: "";
  position: absolute;
  left: -1.5rem;
  top: .85rem;
  width: 1rem;
  height: 2px;
  background: var(--border);
}
.dep-item-leaf .dep-row { padding: .15rem 0; }
.dep-row {
  display: flex;
  align-items: center;
  gap: .45rem;
  flex-wrap: wrap;
}
.dep-name { font-weight: 600; color: var(--text); }
.dep-ver { color: var(--muted); font-size: .92em; }
.dep-meta-group {
  display: inline-flex;
  align-items: center;
  gap: .35rem;
  flex-wrap: wrap;
  margin-left: auto;
}
.dep-chip {
  font-size: .62rem;
  padding: .12rem .4rem;
  border-radius: 999px;
  background: var(--surface-2);
  color: var(--muted);
  border: 1px solid var(--border);
  white-space: nowrap;
}
.dep-chip-dim { opacity: .85; }
.dep-chip-dev { background: rgba(99, 102, 241, .08); color: #6366f1; border-color: rgba(99, 102, 241, .2); }
.dep-chip-ok { background: rgba(34, 197, 94, .08); color: #16a34a; border-color: rgba(34, 197, 94, .2); }
.dep-cve-chip {
  font-size: .62rem;
  padding: .12rem .45rem;
  border-radius: 999px;
  font-weight: 600;
  white-space: nowrap;
}
.dep-nested { margin: .15rem 0; }
.dep-nested > .dep-summary {
  padding: .35rem 0;
  background: transparent;
  border-bottom: none;
  font-size: .78rem;
}
.dep-nested[open] > .dep-summary { border-bottom: none; }
.dep-hidden { display: none !important; }
.dep-orphans-block {
  margin-top: 1.25rem;
  border: 1px dashed var(--border);
  border-radius: var(--radius);
  padding: .75rem 1rem;
  background: var(--surface);
}
.dep-orphans-summary {
  cursor: pointer;
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  list-style: none;
}
.dep-orphans-summary::-webkit-details-marker { display: none; }
.dep-count-chip {
  display: inline-block;
  margin-left: .35rem;
  padding: .1rem .4rem;
  border-radius: 999px;
  background: var(--surface-2);
  font-size: .68rem;
}
.dep-orphan-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr));
  gap: .45rem;
  margin-top: .75rem;
}
.dep-orphan-chip {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: .25rem .4rem;
  padding: .45rem .6rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm, 6px);
  background: var(--surface-2);
  font-size: .72rem;
}
.dep-orphan-cve { border-left: 2px solid var(--danger); }

@media print {
  .dash-panel { break-inside: avoid; }
}

.empty-state {
  padding: 1.5rem;
  text-align: center;
  color: var(--muted);
  background: var(--surface-2);
  border: 1px dashed var(--border);
  border-radius: var(--radius);
}

.charts-row { display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap; }
.chart-legend { flex: 1; min-width: 140px; }
.legend-item {
  display: flex;
  align-items: center;
  gap: .5rem;
  margin-bottom: .4rem;
  font-size: .78rem;
}
.legend-dot {
  width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
}
.legend-count { margin-left: auto; font-weight: 600; font-variant-numeric: tabular-nums; }

.verdict-bars { margin-top: .5rem; }
.verdict-bar-row {
  display: grid;
  grid-template-columns: 72px 1fr 36px;
  align-items: center;
  gap: .65rem;
  margin-bottom: .45rem;
  font-size: .75rem;
}
.verdict-bar-track {
  height: 10px;
  background: var(--surface-2);
  border-radius: 5px;
  overflow: hidden;
  border: 1px solid var(--border);
}
.verdict-bar-fill { height: 100%; border-radius: 4px; }
.bar-fix-now { background: var(--danger); }
.bar-fix-soon { background: var(--warn); }
.bar-ok { background: var(--ok); }
.bar-exploitable { background: var(--accent); }

/* ── Sections ── */
.section { margin-bottom: 2.25rem; }
.section-head {
  display: flex;
  align-items: baseline;
  gap: .75rem;
  margin-bottom: 1.1rem;
  padding-bottom: .65rem;
  border-bottom: 2px solid var(--border);
}
.section-head h2 {
  font-size: 1rem;
  font-weight: 700;
  color: var(--text);
  text-transform: uppercase;
  letter-spacing: .06em;
}
.section-head .count {
  font-size: .75rem;
  color: var(--muted);
  font-weight: 500;
}
.section-head .badge-alert {
  margin-left: auto;
  background: var(--danger-soft);
  color: var(--danger);
  font-size: .68rem;
  font-weight: 600;
  padding: .2rem .55rem;
  border-radius: 6px;
  text-transform: uppercase;
  letter-spacing: .04em;
}

/* ── Priority upgrade rollup ── */
.rollup-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.rollup-card {
  position: relative;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  box-shadow: var(--shadow);
}
.rollup-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: .5rem;
  margin-bottom: .25rem;
}
.rollup-pkg { font-weight: 700; font-size: .9rem; }
.rollup-inner { padding: .85rem 1rem 1rem; }
.rollup-accent {
  height: 3px;
  background: linear-gradient(90deg, var(--accent), #fb923c);
}
.rollup-p0 .rollup-accent { background: linear-gradient(90deg, var(--danger), #f87171); }
.rollup-p1 .rollup-accent { background: linear-gradient(90deg, var(--warn), #fbbf24); }
.rollup-p2 .rollup-accent { background: linear-gradient(90deg, var(--poc), #a78bfa); }
.rollup-p3 .rollup-accent { background: linear-gradient(90deg, var(--info), #38bdf8); }
.rollup-p4 .rollup-accent { background: linear-gradient(90deg, #94a3b8, #cbd5e1); }
.rollup-metrics {
  display: flex;
  flex-wrap: wrap;
  gap: .65rem;
  margin: .15rem 0 .65rem;
}
.rollup-metric {
  font-size: .72rem;
  color: var(--muted);
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: .35rem .55rem;
}
.rollup-metric strong {
  color: var(--text);
  font-size: .85rem;
  margin-right: .2rem;
}
.rollup-fix { font-size: .75rem; }
.rollup-fix-label {
  display: block;
  font-size: .62rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  margin-bottom: .15rem;
}
.rollup-fix-ver {
  font-size: .95rem;
  font-weight: 700;
  padding: .15rem .45rem;
  border-radius: 6px;
}
.rollup-affected {
  font-size: .68rem;
  color: var(--text-2);
  margin-top: .35rem;
  padding-top: .45rem;
  border-top: 1px dashed var(--border);
}
.rollup-affected-label {
  display: block;
  font-size: .58rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  margin-bottom: .15rem;
}
.section-decisions { border-left: 3px solid var(--info); padding-left: .85rem; }
.decision-list { display: flex; flex-direction: column; gap: .5rem; }
.decision-row {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: .65rem .85rem;
}
.decision-main { font-size: .78rem; }
.decision-reason { font-size: .72rem; margin-top: .2rem; }
.finding-path {
  font-size: .72rem;
  color: var(--muted);
  margin-top: .25rem;
  font-family: var(--font);
}

.coverage-banner {
  border-radius: var(--radius);
  padding: .75rem 1rem;
  margin-bottom: 1.25rem;
  font-size: .78rem;
  display: flex;
  flex-direction: column;
  gap: .25rem;
}
.coverage-incomplete {
  background: rgba(239, 68, 68, .08);
  border: 1px solid rgba(239, 68, 68, .35);
  color: var(--danger);
}
.coverage-partial {
  background: rgba(245, 158, 11, .08);
  border: 1px solid rgba(245, 158, 11, .35);
  color: var(--warn);
}
.dossier-upgrade-card {
  background: linear-gradient(135deg, rgba(255,247,237,.5) 0%, var(--surface) 60%);
  border: 1px solid rgba(234,88,12,.2);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius);
  padding: .85rem 1rem;
  margin-bottom: 1rem;
}
.dossier-upgrade-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: .75rem;
  flex-wrap: wrap;
}
.dossier-upgrade-fix { font-size: .85rem; }
.dossier-upgrade-note { font-size: .72rem; margin: .45rem 0 0; }
.dossier-cve-table { margin-top: .5rem; }

/* ── Package profiles ── */
.pkg-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.pkg-card {
  display: block;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1rem 1.15rem;
  box-shadow: var(--shadow);
  color: inherit;
  text-decoration: none;
}
.pkg-card-link {
  cursor: pointer;
  transition: border-color .15s ease, box-shadow .15s ease, transform .15s ease;
}
.pkg-card-link:hover {
  border-color: var(--info);
  box-shadow: 0 4px 20px rgba(2,132,199,.12);
  transform: translateY(-1px);
}
.pkg-card-link:focus-visible {
  outline: 2px solid var(--info);
  outline-offset: 2px;
}
.pkg-card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: .5rem;
  margin-bottom: .5rem;
}
.pkg-name { font-weight: 700; font-size: .95rem; color: var(--text); }
.pkg-version { color: var(--muted); font-weight: 500; }
.pkg-desc {
  font-size: .78rem;
  color: var(--text-2);
  line-height: 1.45;
  margin-bottom: .65rem;
}
.pkg-stats {
  display: flex;
  flex-wrap: wrap;
  gap: .35rem;
}
.stat-pill {
  font-size: .68rem;
  padding: .2rem .5rem;
  border-radius: 6px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--text-2);
}
.stat-pill-dl { background: #eff6ff; border-color: #bfdbfe; color: #1d4ed8; }
.stat-pill-dl-primary { font-weight: 700; font-size: .72rem; }
.stat-pill-pop { background: #f5f3ff; border-color: #ddd6fe; color: #6d28d9; }
.stat-pill-scope { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
.stat-pill-dev { background: #fefce8; border-color: #fef08a; color: #854d0e; }
.stat-pill-lic { background: #fff7ed; border-color: #fed7aa; color: #c2410c; }
.stat-pill-link {
  background: var(--accent-soft);
  border-color: rgba(234,88,12,.35);
  color: var(--accent);
  text-decoration: none;
  font-weight: 600;
}
.stat-pill-link:hover { filter: brightness(0.95); box-shadow: 0 1px 4px rgba(234,88,12,.15); }

/* ── Package profile cards (rollup + accordion) ── */
.pkg-profile {
  background: linear-gradient(135deg, rgba(255,247,237,.65) 0%, var(--surface) 55%);
  border: 1px solid rgba(234,88,12,.18);
  border-left: 3px solid var(--accent);
  border-radius: 10px;
  padding: .85rem 1rem;
  margin: .65rem 0 .75rem;
}
.pkg-profile-head {
  display: flex;
  align-items: flex-start;
  gap: .65rem;
  margin-bottom: .45rem;
}
.pkg-profile-icon {
  color: var(--accent);
  font-size: 1.1rem;
  line-height: 1;
  margin-top: .1rem;
}
.pkg-profile-title { flex: 1; min-width: 0; }
.pkg-profile-name { font-weight: 700; font-size: .88rem; color: var(--text); }
.pkg-profile-ver { color: var(--muted); font-weight: 500; font-size: .78rem; margin-left: .25rem; }
.pkg-profile-desc {
  font-size: .76rem;
  line-height: 1.55;
  color: var(--text-2);
  margin: 0 0 .65rem;
}
.eco-badge {
  font-size: .58rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .06em;
  padding: .2rem .45rem;
  border-radius: 999px;
  white-space: nowrap;
}
.eco-badge-hot { background: #fef2f2; color: var(--danger); border: 1px solid #fecaca; }
.eco-badge-wide { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
.eco-badge-pop { background: #f5f3ff; color: #6d28d9; border: 1px solid #ddd6fe; }

.finding-eco-strip { margin-top: .55rem; }
.finding-eco-strip .pkg-stats { gap: .3rem; }
.finding-eco-strip .stat-pill { font-size: .62rem; padding: .15rem .4rem; }

.accord-eco {
  display: inline-flex;
  flex-wrap: wrap;
  gap: .3rem;
  margin-left: .35rem;
}
.accord-pill {
  font-size: .58rem;
  font-weight: 600;
  padding: .12rem .4rem;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text-2);
}
.accord-pill-dl { background: #eff6ff; border-color: #bfdbfe; color: #1d4ed8; }
.accord-pill-lic { background: #fff7ed; border-color: #fed7aa; color: #c2410c; }

.pkg-findings-count {
  font-size: .72rem;
  color: var(--danger);
  font-weight: 600;
  white-space: nowrap;
}

/* ── Finding cards ── */
.finding-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 1rem;
  overflow: hidden;
  box-shadow: var(--shadow);
}
.finding-card.action { border-left: 4px solid var(--danger); }
.finding-card.soon { border-left: 4px solid var(--warn); }
.finding-top {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 1rem;
  padding: 1rem 1.25rem;
  align-items: start;
  border-bottom: 1px solid var(--border);
  background: var(--surface-2);
}
@media (max-width: 700px) { .finding-top { grid-template-columns: 1fr; } }

.priority-pill {
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  min-width: 52px;
  padding: .45rem .6rem;
  border-radius: 8px;
  font-weight: 700;
  font-size: .85rem;
  text-align: center;
}
.priority-p0 { background: var(--danger-soft); color: var(--danger); border: 1px solid #fecaca; }
.priority-p1 { background: var(--warn-soft); color: var(--warn); border: 1px solid #fde68a; }
.priority-p2 { background: #f5f3ff; color: var(--poc); border: 1px solid #ddd6fe; }
.priority-p3 { background: #eff6ff; color: var(--info); border: 1px solid #bfdbfe; }
.priority-p4 { background: var(--surface-2); color: var(--muted); border: 1px solid var(--border); }
.priority-sub { font-size: .58rem; font-weight: 500; margin-top: .15rem; opacity: .85; }

.finding-title { min-width: 0; }
.finding-cve { font-size: .95rem; font-weight: 700; color: var(--text); }
.finding-advisory { font-size: .72rem; color: var(--muted); margin-top: .15rem; }
.finding-cve-desc {
  font-size: .78rem;
  color: var(--text-2);
  line-height: 1.5;
  margin-top: .45rem;
  padding: .55rem .65rem;
  background: var(--surface);
  border-left: 3px solid var(--info);
  border-radius: 0 6px 6px 0;
}
.finding-pkg-line {
  font-size: .78rem;
  color: var(--text-2);
  margin-top: .35rem;
}
.finding-path { color: var(--muted); font-size: .72rem; }

.verdict-pill {
  font-size: .72rem;
  font-weight: 700;
  padding: .35rem .65rem;
  border-radius: 8px;
  text-transform: uppercase;
  letter-spacing: .04em;
  white-space: nowrap;
}
.verdict-danger { background: var(--danger-soft); color: var(--danger); }
.verdict-warn { background: var(--warn-soft); color: var(--warn); }
.verdict-ok { background: var(--ok-soft); color: var(--ok); }

.finding-body { padding: 1rem 1.25rem 1.15rem; }

.signals-row { display: flex; flex-wrap: wrap; gap: .35rem; margin-bottom: .85rem; }
.badge {
  display: inline-block;
  font-size: .65rem;
  font-weight: 600;
  padding: .18rem .45rem;
  border-radius: 5px;
  letter-spacing: .02em;
}
.badge-kev { background: var(--danger-soft); color: var(--danger); border: 1px solid #fecaca; }
.badge-link {
  text-decoration: none;
  cursor: pointer;
  transition: filter .12s ease, box-shadow .12s ease;
}
.badge-link:hover {
  filter: brightness(0.92);
  box-shadow: 0 1px 4px rgba(15,23,42,.12);
}
.badge-nuc, .badge-msf, .badge-edb { background: var(--warn-soft); color: var(--warn); border: 1px solid #fde68a; }
.badge-poc { background: #f5f3ff; color: var(--poc); border: 1px solid #ddd6fe; }
.badge-epss { background: var(--ok-soft); color: var(--ok); border: 1px solid #a7f3d0; }

/* ── Fix / upgrade path ── */
.fix-block {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: .85rem 1rem;
  margin-bottom: .85rem;
}
.fix-label {
  font-size: .65rem;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--muted);
  margin-bottom: .45rem;
}
.fix-path {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: .5rem .65rem;
}
.ver-from, .ver-to {
  font-size: 1rem;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  padding: .2rem .45rem;
  border-radius: 6px;
  background: var(--surface);
  border: 1px solid var(--border);
}
.ver-to { border-color: var(--ok); background: var(--ok-soft); color: #047857; }
.ver-arrow { color: var(--muted); font-size: 1.1rem; }
.jump-badge {
  font-size: .68rem;
  font-weight: 600;
  padding: .25rem .55rem;
  border-radius: 6px;
}
.jump-patch { background: var(--ok-soft); color: var(--ok); border: 1px solid #a7f3d0; }
.jump-minor { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
.jump-major { background: var(--danger-soft); color: var(--danger); border: 1px solid #fecaca; }
.jump-none { background: var(--surface-2); color: var(--muted); border: 1px solid var(--border); }
.fix-hint { font-size: .72rem; color: var(--muted); width: 100%; margin-top: .15rem; }

.receipts { margin-top: .5rem; }
.receipts-title {
  font-size: .65rem;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--muted);
  margin-bottom: .4rem;
}
.receipts ul { list-style: none; padding: 0; }
.receipts li {
  font-size: .76rem;
  color: var(--text-2);
  padding: .3rem 0;
  border-bottom: 1px solid var(--border);
  display: flex;
  gap: .5rem;
  align-items: flex-start;
}
.receipts li:last-child { border-bottom: none; }
.receipts a { color: var(--info); text-decoration: none; font-size: .7rem; white-space: nowrap; }
.receipts a:hover { text-decoration: underline; }

/* ── Compact table (non-action findings) ── */
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); }
table { width: 100%; border-collapse: collapse; font-size: .78rem; }
th {
  text-align: left;
  padding: .65rem .85rem;
  background: var(--surface-2);
  font-size: .65rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  border-bottom: 1px solid var(--border);
}
td {
  padding: .55rem .85rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: #fafbfc; }

.disclaimer {
  font-size: .72rem;
  color: var(--muted);
  padding: .85rem 1rem;
  background: var(--surface-2);
  border-radius: 8px;
  border: 1px dashed var(--border);
  margin-top: 1rem;
}

.report-footer {
  text-align: center;
  padding: 2rem 0 0;
  color: var(--muted);
  font-size: .72rem;
  border-top: 1px solid var(--border);
  margin-top: 2rem;
}

.dim { color: var(--muted); }
a { color: var(--info); }
code { font-size: .85em; background: var(--surface-2); padding: .1rem .3rem; border-radius: 4px; }

@media print {
  body { background: #fff; }
  .report-header { break-inside: avoid; }
  .finding-card { break-inside: avoid; page-break-inside: avoid; }
}
</style>`
