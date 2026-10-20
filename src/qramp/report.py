# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.report — Layer 5: static artefacts, plus the verify loop that closes
the pipeline. No server required; the dashboard is a single static HTML file.
"""
from __future__ import annotations

import csv
import hashlib
import html
import json
import os
from dataclasses import replace
from datetime import datetime, timezone

import yaml

from .model import Inventory


# ---------------- dashboard ----------------
def dashboard(cbom_path: str, out_html: str, provider_map: dict | None = None,
              vex_doc: dict | None = None, history: list | None = None) -> None:
    inv = Inventory.load(cbom_path)
    # apply VEX exceptions so the table can show what has been triaged
    n_suppressed = 0
    if vex_doc:
        from . import vex as _vex
        _vex.apply(inv, _vex.parse(vex_doc))
    tier_colour = {"P0": "#C00000", "P1": "#C55A11", "P2": "#BF9000",
                   "P3": "#548235", "OK": "#2F5597", None: "#808080"}
    rows = []
    for a in inv.assets:
        owners = ", ".join(sorted(a.owners())) or "—"
        exp = a.exposure_class or "unknown"
        tier = a.tier or "—"
        supp = None
        if vex_doc:
            from . import vex as _vex
            supp = _vex.suppression_for(a)
        is_supp = supp is not None
        if is_supp:
            n_suppressed += 1
        status_cell = ""
        if is_supp:
            just = html.escape(supp.get("justification") or supp.get("status") or "accepted")
            detail = html.escape((supp.get("detail") or "").strip())
            title = f" title='{detail}'" if detail else ""
            status_cell = (f"<span class='vexbadge'{title}>VEX: {just}</span>")
        row_cls = "suppressed" if is_supp else ""
        # provenance tooltip: rule id, rationale, and governing standards
        prov_bits = []
        if a.rule_id:
            prov_bits.append(f"rule: {a.rule_id}")
        if a.rationale:
            prov_bits.append(a.rationale)
        if a.references:
            cites = "; ".join(
                (rf.get("standard", "") + (f" {rf['section']}" if rf.get("section") else ""))
                for rf in a.references if isinstance(rf, dict))
            if cites:
                prov_bits.append(f"refs: {cites}")
        prov_title = html.escape(" — ".join(prov_bits))
        exp_cell = (f"<span title='{prov_title}' class='exp-cite'>{html.escape(exp)}</span>"
                    if prov_title else html.escape(exp))
        rows.append(
            f"<tr data-asset='{a.asset_id}' data-tier='{a.tier or ''}' "
            f"data-exposure='{html.escape(exp)}' data-suppressed='{'1' if is_supp else '0'}'"
            f"{f' class={chr(34)}{row_cls}{chr(34)}' if row_cls else ''}>"
            f"<td><code>{html.escape(a.display)}</code></td>"
            f"<td>{exp_cell}</td>"
            f"<td style='color:{tier_colour.get(a.tier)};font-weight:700'>{tier}</td>"
            f"<td>{len(a.occurrences)}</td>"
            f"<td>{html.escape(owners)}</td>"
            f"<td>{html.escape(', '.join(sorted(a.tag_union())) or '')}</td>"
            f"<td>{status_cell}</td>"
            f"</tr>"
        )
    counts: dict = {}
    for a in inv.assets:
        counts[a.tier] = counts.get(a.tier, 0) + 1
    chips = " ".join(
        f"<span class='chip' style='background:{tier_colour.get(t)}'>{t or '—'}: {c}</span>"
        for t, c in sorted(counts.items(), key=lambda x: str(x[0])))

    from .svggraph import dependency_svg, chain_svg
    dep_graph = dependency_svg(inv)
    cert_graph = chain_svg(inv)

    # readiness section (best-effort; needs SBOM components + a provider map)
    readiness_html = _readiness_section(inv, provider_map)
    sim_html = _simulation_section(inv, provider_map)
    timeline_html = _timeline_section(inv, cbom_path, history)

    # filter buttons: tiers present + exposure classes present
    tiers_present = [t for t in ["P0", "P1", "P2", "P3", "OK"] if t in counts]
    exposures_present = sorted({(a.exposure_class or "unknown") for a in inv.assets})
    tier_btns = "".join(
        f"<button class='filt' data-dim='tier' data-val='{t}' "
        f"style='border-color:{tier_colour.get(t)}'>{t}</button>" for t in tiers_present)
    exp_btns = "".join(
        f"<button class='filt' data-dim='exposure' data-val='{html.escape(e)}'>{html.escape(e)}</button>"
        for e in exposures_present)

    # a "hide suppressed" toggle only appears when there is something to hide
    supp_toggle = ""
    if n_suppressed:
        supp_toggle = (
            f"&nbsp;·&nbsp; <button class='filt' id='togglesupp'>"
            f"hide {n_suppressed} suppressed</button>")

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>QRAMP dashboard</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#222}}
h1{{color:#1F3864}} h2{{color:#1F3864;margin-top:2rem;font-size:1.15rem}}
.chip{{color:#fff;padding:.2rem .6rem;border-radius:1rem;margin-right:.4rem;font-size:.85rem}}
table{{border-collapse:collapse;width:100%;margin-top:1rem;font-size:.9rem}}
th,td{{border:1px solid #B4C7E7;padding:.4rem .6rem;text-align:left}}
th{{background:#D9E2F3}} code{{font-size:.85rem}}
.graph{{border:1px solid #E2E8F0;border-radius:8px;padding:1rem;margin-top:1rem;overflow-x:auto}}
.meta{{color:#666;font-size:.85rem;margin-top:1.5rem}}
.filters{{margin:.8rem 0}}
.filt{{background:#fff;border:1.5px solid #B4C7E7;border-radius:1rem;padding:.2rem .7rem;
  margin:.15rem;font-size:.8rem;cursor:pointer;color:#333}}
.filt.on{{background:#1F3864;color:#fff;border-color:#1F3864}}
tr.hidden{{display:none}}
tr.match{{outline:2px solid #1F3864;outline-offset:-2px;background:#EAF1FB}}
.qramp-cap{{cursor:pointer}}
.qramp-cap.dim{{opacity:.25}}
.qramp-cap.hot rect{{stroke:#1F3864;stroke-width:3}}
.ready{{border:1px solid #E2E8F0;border-radius:8px;padding:1rem;margin-top:1rem;background:#F7FAFF}}
.ready ol{{margin:.4rem 0 0 1.2rem;padding:0}} .ready li{{margin:.35rem 0}}
.roi{{color:#548235;font-weight:700}} .unlocks{{color:#1F3864;font-weight:600}}
tr.suppressed td code{{text-decoration:line-through}}
tr.suppressed{{color:#9AA5B1;background:#FAFBFC}}
tr.suppressed td{{opacity:.75}}
.vexbadge{{background:#E2E8F0;color:#475569;border-radius:1rem;padding:.1rem .5rem;
  font-size:.75rem;white-space:nowrap}}
tr.hide-suppressed{{display:none}}
.exp-cite{{border-bottom:1px dotted #94a3b8;cursor:help}}
.sim{{border:1px solid #E2E8F0;border-radius:8px;padding:1rem;margin-top:1rem;background:#F7FAFF}}
.sim select{{font-size:.9rem;padding:.2rem;margin-left:.3rem}}
.sim-stats{{display:flex;gap:1.5rem;margin:.8rem 0}}
.sim-stat{{display:flex;flex-direction:column}}
.sim-num{{font-size:1.6rem;font-weight:700;color:#1F3864}}
.sim-lbl{{font-size:.75rem;color:#666}}
.sim-unlocks{{color:#548235;font-weight:600;font-size:.85rem;min-height:1.1rem}}
.sim-bars{{display:flex;flex-direction:column;gap:.35rem;max-width:520px}}
.sim-barrow{{display:flex;align-items:center;gap:.5rem;font-size:.8rem}}
.sim-barlbl{{width:1.6rem;font-weight:700}}
.sim-bartrack{{position:relative;flex:1;height:14px;background:#EEF2F7;border-radius:4px;overflow:hidden}}
.sim-barghost{{position:absolute;left:0;top:0;height:14px;background:#D6DCE5;border-radius:4px}}
.sim-barfill{{position:absolute;left:0;top:0;height:14px;border-radius:4px;transition:width .4s ease}}
.sim-barcnt{{width:6.5rem;color:#555}}
.tl{{border:1px solid #E2E8F0;border-radius:8px;padding:1rem;margin-top:1rem;background:#F7FAFF}}
.tl-head{{font-size:.9rem;color:#333;margin-bottom:.4rem}}
.tl-trend{{font-weight:700;text-transform:capitalize}}
.tl-chart{{overflow-x:auto}}
kbd{{background:#eef;border-radius:3px;padding:0 .3rem;font-size:.8rem}}</style></head><body>
<h1>QRAMP — cryptographic inventory</h1>
<p>{len(inv)} assets · {inv.occurrence_count()} occurrences</p>
<p>{chips}</p>
{timeline_html}
{readiness_html}
{sim_html}
<h2>Dependency graph — which library provides which capability</h2>
<p class="meta">Hover a capability to highlight its row below; click to pin the filter.</p>
<div class="graph" id="depgraph">{dep_graph}</div>
<h2>Certificate trust chains — the weakest link</h2>
<div class="graph">{cert_graph}</div>
<h2>Asset inventory</h2>
<div class="filters">Filter:
  <span>tier</span> {tier_btns}
  &nbsp;·&nbsp; <span>exposure</span> {exp_btns}{supp_toggle}
  <button class="filt" id="clearf">clear</button>
</div>
<table id="assets"><thead><tr><th>Asset</th><th>Exposure</th><th>Tier</th>
<th>Occurrences</th><th>Owners</th><th>Tags</th><th>Status</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p class="meta">Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} · static file, no server required.</p>
<script>{_DASHBOARD_JS}</script>
</body></html>"""
    open(out_html, "w", encoding="utf-8").write(doc)


def _readiness_section(inv, provider_map) -> str:
    """Render the ROI-ranked upgrade recommendations, if computable."""
    if not inv.components:
        return ""
    try:
        import os
        import yaml
        from .readiness import readiness_report
        if provider_map is None:
            path = os.path.join(os.path.dirname(__file__), "data", "provider-map.yaml")
            provider_map = yaml.safe_load(open(path, encoding="utf-8"))
        rep = readiness_report(inv, provider_map)
    except Exception:
        return ""
    if not rep.get("pqc_migration_assets"):
        return ""
    pct = rep["readiness_pct"]
    bar_colour = "#548235" if pct >= 66 else "#BF9000" if pct >= 33 else "#C00000"
    items = []
    for o in rep["recommended_upgrades"][:5]:
        by = ", ".join(f"{t}×{n}" for t, n in sorted(o["by_tier"].items()))
        items.append(
            f"<li><b>{html.escape(o['component'])}</b> "
            f"<code>{html.escape(o['upgrade'])}</code> — "
            f"<span class='unlocks'>unlocks {html.escape(', '.join(o['unlocks']))}</span>, "
            f"unblocks <b>{o['unblocks']}</b> asset(s) ({html.escape(by)}) "
            f"<span class='roi'>ROI {o['roi_score']}</span></li>")
    ups = ("<ol>" + "".join(items) + "</ol>") if items else \
        "<p>No library upgrade would unblock a blocked asset.</p>"
    return f"""<h2>Migration readiness</h2>
<div class="ready">
<p><b>{pct}%</b> of PQC-migration assets are already migratable
({rep['already_migratable']}/{rep['pqc_migration_assets']}).
{rep['migration_blocked']} blocked · {rep['blocked_addressable_by_upgrade']} addressable by a library upgrade.</p>
<div style="background:#e6e6e6;border-radius:6px;height:12px;width:100%;max-width:420px">
  <div style="background:{bar_colour};height:12px;border-radius:6px;width:{max(pct,2):.0f}%"></div></div>
<p style="margin-top:.6rem"><b>Recommended upgrades (ROI-ranked):</b></p>
{ups}
</div>"""


def _simulation_section(inv, provider_map) -> str:
    """Precompute the before/after of each candidate upgrade (and 'apply all')
    and embed them so the dashboard can switch between them interactively —
    without a server, since the file is static."""
    if not inv.components:
        return ""
    try:
        import json as _json
        import os
        import yaml
        from .readiness import upgrade_options
        from .simulate import simulate
        if provider_map is None:
            path = os.path.join(os.path.dirname(__file__), "data", "provider-map.yaml")
            provider_map = yaml.safe_load(open(path, encoding="utf-8"))
        options = upgrade_options(inv, provider_map)
    except Exception:
        return ""
    if not options:
        return ""

    # baseline (no upgrade) from the current inventory
    base = simulate(inv, provider_map, {})   # empty upgrade -> current state
    scenarios = [{
        "id": "none", "label": "No upgrade (current)",
        "blocked": base["blocked_before"],
        "readiness": base["readiness_before_pct"],
        "tiers": base["blocked_tier_before"],
        "unlocks": [], "unblocked": 0,
    }]
    # one scenario per candidate upgrade
    for o in options:
        rep = simulate(inv, provider_map, {o.component.lower(): o.to_version})
        scenarios.append({
            "id": f"{o.component}={o.to_version}",
            "label": f"Upgrade {o.component} → {o.to_version}",
            "blocked": rep["blocked_after"],
            "readiness": rep["readiness_after_pct"],
            "tiers": rep["blocked_tier_after"],
            "unlocks": rep["pq_capabilities_added"],
            "unblocked": rep["unblocked"],
        })
    # an "apply all" scenario if there is more than one candidate
    if len(options) > 1:
        combo = {o.component.lower(): o.to_version for o in options}
        rep = simulate(inv, provider_map, combo)
        scenarios.append({
            "id": "all",
            "label": "Apply all recommended upgrades",
            "blocked": rep["blocked_after"],
            "readiness": rep["readiness_after_pct"],
            "tiers": rep["blocked_tier_after"],
            "unlocks": rep["pq_capabilities_added"],
            "unblocked": rep["unblocked"],
        })

    data = html.escape(__import__("json").dumps(scenarios), quote=True)
    opts_html = "".join(
        f"<option value='{i}'>{html.escape(s['label'])}</option>"
        for i, s in enumerate(scenarios))
    return f"""<h2>Upgrade simulation — what a bump would change</h2>
<div class="sim" data-scenarios="{data}">
  <label>Pick an upgrade to model:
    <select id="sim-select">{opts_html}</select></label>
  <div class="sim-stats">
    <div class="sim-stat"><span class="sim-num" id="sim-blocked">–</span>
      <span class="sim-lbl">migration-blocked</span></div>
    <div class="sim-stat"><span class="sim-num" id="sim-ready">–</span>
      <span class="sim-lbl">readiness</span></div>
    <div class="sim-stat"><span class="sim-num" id="sim-unblocked">–</span>
      <span class="sim-lbl">newly unblocked</span></div>
  </div>
  <div id="sim-unlocks" class="sim-unlocks"></div>
  <p style="margin:.6rem 0 .2rem;font-size:.85rem;color:#666">Migration-blocked assets by tier:</p>
  <div id="sim-bars" class="sim-bars"></div>
</div>"""


def _timeline_section(inv, cbom_path, history) -> str:
    """When historical CBOMs are supplied, embed the migration-progress trend
    chart and headline numbers so progress and current state sit in one view.
    The current CBOM is the latest point in the series."""
    if not history:
        return ""
    try:
        from .timeline import build, summarise, deltas, _point
        from .svggraph import timeline_svg
        points = build(list(history))
        # append the current inventory as the latest point (dedup by path)
        cur = _point(inv, "current")
        points = [p for p in points if p.label != "current"]
        points.append(cur)
        points.sort(key=lambda p: (p.timestamp or "", p.label))
    except Exception:
        return ""
    if len(points) < 2:
        return ""                       # need at least two scans for a trend
    summ = summarise(points)
    dls = deltas(points)
    # choose which tiers to draw: any that appear with a non-zero count
    present = set()
    for p in points:
        for t, c in p.tiers.items():
            if c and t in ("P0", "P1", "P2", "P3"):
                present.add(t)
    series = tuple(t for t in ("P0", "P1", "P2", "P3") if t in present) or ("P0", "P1")
    svg = timeline_svg(points, series=series)
    trend = summ.get("trend", "flat")
    trend_colour = {"improving": "#548235", "worsening": "#C00000",
                    "flat": "#BF9000"}.get(trend, "#666")
    change = summ.get("urgent_change", 0)
    change_str = f"{change:+d}" if change else "0"
    return f"""<h2>Migration progress — trend across {summ.get('scans', 0)} scans</h2>
<div class="tl">
  <div class="tl-head">
    <span class="tl-trend" style="color:{trend_colour}">{trend}</span>
    · urgent (P0+P1) {summ.get('urgent_first', 0)} → <b>{summ.get('urgent_last', 0)}</b>
    ({change_str}) · <b>{summ.get('net_remediated', 0)}</b> net assets remediated
  </div>
  <div class="tl-chart">{svg}</div>
</div>"""


# minimal, dependency-free interactivity: table filtering + graph↔row highlight
_DASHBOARD_JS = r"""
(function(){
  var active = {tier:null, exposure:null};
  var hideSuppressed = false;
  var rows = Array.prototype.slice.call(document.querySelectorAll('#assets tbody tr'));
  function apply(){
    rows.forEach(function(r){
      var ok = true;
      if(active.tier && r.getAttribute('data-tier')!==active.tier) ok=false;
      if(active.exposure && r.getAttribute('data-exposure')!==active.exposure) ok=false;
      r.classList.toggle('hidden', !ok);
      var supp = r.getAttribute('data-suppressed')==='1';
      r.classList.toggle('hide-suppressed', hideSuppressed && supp);
    });
  }
  document.querySelectorAll('.filt').forEach(function(b){
    b.addEventListener('click', function(){
      if(b.id==='clearf'){active={tier:null,exposure:null}; hideSuppressed=false;
        document.querySelectorAll('.filt').forEach(function(x){x.classList.remove('on')});
        var t=document.getElementById('togglesupp');
        if(t){t.textContent='hide '+document.querySelectorAll('#assets tr[data-suppressed="1"]').length+' suppressed';}
        apply(); return;}
      if(b.id==='togglesupp'){
        hideSuppressed=!hideSuppressed; b.classList.toggle('on', hideSuppressed);
        var n=document.querySelectorAll('#assets tr[data-suppressed="1"]').length;
        b.textContent=(hideSuppressed?'show ':'hide ')+n+' suppressed';
        apply(); return;}
      var dim=b.getAttribute('data-dim'), val=b.getAttribute('data-val');
      if(active[dim]===val){active[dim]=null; b.classList.remove('on');}
      else{
        document.querySelectorAll('.filt[data-dim="'+dim+'"]').forEach(function(x){x.classList.remove('on')});
        active[dim]=val; b.classList.add('on');
      }
      apply();
    });
  });
  // graph capability node <-> table row cross highlight
  var caps = document.querySelectorAll('#depgraph .qramp-cap');
  function rowFor(id){return document.querySelector('#assets tr[data-asset="'+id+'"]');}
  caps.forEach(function(g){
    var id=g.getAttribute('data-asset');
    g.addEventListener('mouseenter', function(){
      var r=rowFor(id); if(r){r.classList.add('match'); r.scrollIntoView({block:'nearest'});}
      g.classList.add('hot');
    });
    g.addEventListener('mouseleave', function(){
      var r=rowFor(id); if(r) r.classList.remove('match');
      g.classList.remove('hot');
    });
    g.addEventListener('click', function(){
      // pin: dim other capability nodes, keep only edges to this one prominent
      var on=g.classList.contains('pinned');
      caps.forEach(function(x){x.classList.remove('pinned');x.classList.toggle('dim',!on&&x!==g);});
      if(!on) g.classList.add('pinned'); else caps.forEach(function(x){x.classList.remove('dim')});
    });
  });
  // hovering a table row highlights its capability node
  rows.forEach(function(r){
    var id=r.getAttribute('data-asset');
    r.addEventListener('mouseenter', function(){
      var g=document.querySelector('#depgraph .qramp-cap[data-asset="'+id+'"]');
      if(g) g.classList.add('hot');
    });
    r.addEventListener('mouseleave', function(){
      var g=document.querySelector('#depgraph .qramp-cap[data-asset="'+id+'"]');
      if(g) g.classList.remove('hot');
    });
  });
  // upgrade simulation: switch the modelled state on select
  var simEl=document.querySelector('.sim');
  if(simEl){
    var scenarios=JSON.parse(simEl.getAttribute('data-scenarios'));
    var tierColour={P0:'#C00000',P1:'#C55A11',P2:'#BF9000',P3:'#548235','—':'#808080'};
    var tierOrder=['P0','P1','P2','P3','—'];
    var baseline=scenarios[0];
    var baseMax=0; tierOrder.forEach(function(t){baseMax=Math.max(baseMax, baseline.tiers[t]||0);});
    baseMax=Math.max(baseMax,1);
    function render(idx){
      var s=scenarios[idx];
      document.getElementById('sim-blocked').textContent=s.blocked;
      document.getElementById('sim-ready').textContent=s.readiness+'%';
      document.getElementById('sim-unblocked').textContent=(idx===0?'–':'+'+s.unblocked);
      var ul=document.getElementById('sim-unlocks');
      ul.textContent = s.unlocks && s.unlocks.length ? ('unlocks '+s.unlocks.join(', ')) : '';
      // bars: for each tier show a bar sized against the baseline max, so the
      // shrink from before -> after is visible on the same scale
      var bars=document.getElementById('sim-bars'); bars.innerHTML='';
      tierOrder.forEach(function(t){
        var n=s.tiers[t]||0; var b0=baseline.tiers[t]||0;
        if(b0===0 && n===0) return;
        var row=document.createElement('div'); row.className='sim-barrow';
        var lbl=document.createElement('span'); lbl.className='sim-barlbl';
        lbl.textContent=t; lbl.style.color=tierColour[t]||'#333';
        var track=document.createElement('span'); track.className='sim-bartrack';
        var ghost=document.createElement('span'); ghost.className='sim-barghost';
        ghost.style.width=(100*b0/baseMax)+'%';
        var fill=document.createElement('span'); fill.className='sim-barfill';
        fill.style.width=(100*n/baseMax)+'%'; fill.style.background=tierColour[t]||'#333';
        track.appendChild(ghost); track.appendChild(fill);
        var cnt=document.createElement('span'); cnt.className='sim-barcnt';
        cnt.textContent=n+(b0!==n?(' (was '+b0+')'):'');
        row.appendChild(lbl); row.appendChild(track); row.appendChild(cnt);
        bars.appendChild(row);
      });
      if(!bars.children.length){
        bars.innerHTML='<span style="color:#548235;font-weight:600">no migration-blocked assets</span>';
      }
    }
    var sel=document.getElementById('sim-select');
    sel.addEventListener('change', function(){render(parseInt(sel.value,10));});
    render(0);
  }
})();
"""


# ---------------- CSV + issue export ----------------
def plan_to_csv(plan_path: str, out_csv: str) -> None:
    doc = yaml.safe_load(open(plan_path, encoding="utf-8"))
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "phase", "type", "owner", "start_month", "duration_months",
                    "target", "acceptance", "rollback", "prerequisites"])
        for t in doc["tasks"]:
            w.writerow([t["id"], t["phase"], t["type"], t["owner"], t["start_month"],
                        t["duration_months"], t["target_display"], t["acceptance"],
                        t["rollback"], ";".join(t["prerequisites"])])


def plan_to_issues(plan_path: str, out_json: str) -> None:
    doc = yaml.safe_load(open(plan_path, encoding="utf-8"))
    issues = []
    for t in doc["tasks"]:
        issues.append({
            "title": f"[{t['id']}] {t['type']} — {t['target_display']}",
            "labels": [f"phase-{t['phase']}", f"owner:{t['owner']}", "pqc-migration"],
            "assignee_group": t["owner"],
            "body": (f"**Action**: {t['action']}\n\n"
                     f"**Prerequisites**: {', '.join(t['prerequisites']) or 'none'}\n"
                     f"**Change window**: {t['window']}\n"
                     f"**Rollback**: {t['rollback']}\n\n"
                     f"**Acceptance (machine-checked by `qramp verify`)**:\n"
                     f"`{t['acceptance']}`\n"),
        })
    json.dump({"issues": issues}, open(out_json, "w", encoding="utf-8"),
              indent=2, ensure_ascii=False)


# ---------------- verify ----------------
def _file_locator(collector, locator):
    if collector == "tls":
        return locator
    if collector.startswith("source-") or collector == "configs":
        head, sep, tail = locator.rpartition(":")
        if sep and tail.isdigit():
            locator = head
    return os.path.abspath(locator)


def _task_inventory(inv, task):
    """A task covers one owner/file or endpoint; other owners remain separate."""
    locations = task.get("target_locations", [])
    if not locations:
        return inv
    wanted = {(x["collector"], x["path"]) for x in locations}
    scoped = Inventory()
    for a in inv.assets:
        occs = [o for o in a.occurrences
                if (o.collector, _file_locator(o.collector, o.locator)) in wanted]
        if occs:
            scoped._assets[a.key] = replace(a, occurrences=occs)
    for cert in inv.certificates:
        if ("certs", os.path.abspath(cert.locator)) in wanted:
            scoped.add_certificate(cert)
    scoped.meta = inv.meta
    return scoped


def _evidence_problem(task, inv):
    locations = task.get("target_locations", [])
    if not locations:
        return "legacy task lacks evidence scope; regenerate the plan from a complete scan"
    stats = {c["name"]: c for c in inv.meta.get("collectors", [])}
    for loc in locations:
        col = loc["collector"]
        if col == "tls":
            continue  # Successful active handshakes supply their own evidence.
        if col not in {"certs", "configs"} and not col.startswith("source-"):
            return f"{col} is a capability declaration, not remediation evidence"
        record = stats.get(col)
        if not record or record.get("skipped"):
            return f"required collector {col} did not complete"
        if record.get("errors"):
            return f"{col} has collection/parse errors: {record['errors'][0]}"
        baseline = task.get("evidence_scope", {}).get(col, {})
        if not baseline.get("root") or record.get("root") != baseline["root"]:
            return f"{col} scan root changed or is undocumented"
        if loc["path"] not in record.get("scanned_paths", []):
            return f"target file is missing or unscanned: {loc['path']}"
        if col.startswith("source-") and (not baseline.get("query_hash") or
                record.get("query_hash") != baseline["query_hash"]):
            return f"{col} detection queries changed or their hash is missing"
    return None


def _verify_index(inv):
    index = {"tls_versions": {}, "tls_groups": {}, "literals": set(), "literal_algorithms": set(),
             "uncertain_literals": set(), "by_algorithm": {},
             "weak_cert": {"weak-key": [], "weak-curve": [], "weak-signature": []}}
    for a in inv.assets:
        atags = a.tag_union()
        for wt in index["weak_cert"]:
            if wt in atags or (wt == "weak-signature" and a.params in ("cert-sig:sha1", "cert-sig:md5")):
                index["weak_cert"][wt].append(a.display)
        index["by_algorithm"].setdefault(a.algorithm, []).append(
            {"key_length": a.key_length, "params": a.params, "display": a.display,
             "locators": [o.locator for o in a.occurrences]})
        for o in a.occurrences:
            if o.collector == "tls" and a.primitive == "protocol":
                index["tls_versions"].setdefault(o.locator, set()).add(a.params)
            if o.collector == "tls" and a.primitive == "key-agreement":
                index["tls_groups"].setdefault(o.locator, set()).add(a.algorithm)
            if o.collector.startswith("source-"):
                if "indeterminate" in o.tags:
                    index["uncertain_literals"].add(a.algorithm)
                else:
                    index["literals"].add(a.display)
                    index["literal_algorithms"].add(a.algorithm)
    return index


def verify(plan_path: str, fresh_cbom_path: str, evidence_out: str,
           phase: int | None = None, active_probe: bool = False,
           scope_path: str | None = None, scope_key: str | None = None,
           attempts: int = 5) -> dict:
    """Evaluate supplied scan evidence. PASS requires complete matching scope.

    Missing/moved files, skipped collectors and changed queries are deferred;
    they never count as successful remediation. This does not run a rescan.
    """
    plan_doc = yaml.safe_load(open(plan_path, encoding="utf-8"))
    inv = Inventory.load(fresh_cbom_path)
    if phase is not None and not any(t["phase"] == phase for t in plan_doc["tasks"]):
        raise ValueError(f"no tasks match requested phase {phase}")
    if active_probe and (not scope_path or not scope_key):
        raise ValueError("active probes require --scope and --scope-key")
    if attempts < 1:
        raise ValueError("attempts must be positive")
    probe_targets, probe_cap = {}, None
    if active_probe:
        from .collectors.tls import load_scope
        from .handshake import local_capability
        for t in load_scope(scope_path, scope_key):
            probe_targets[f"{t['host']}:{t['port']}"] = (t["host"], int(t["port"]))
        probe_cap = local_capability()

    results, evaluated, visiting = [], {}, set()
    tasks = {t["id"]: t for t in plan_doc["tasks"]}
    def evaluate(t):
        tid = t["id"]
        if tid in evaluated:
            return evaluated[tid]
        if tid in visiting:
            raise ValueError("cyclic prerequisites in plan")
        visiting.add(tid)
        blockers = []
        for pre in t.get("prerequisites", []):
            if pre not in tasks or not evaluate(tasks[pre])["passed"]:
                blockers.append(pre)
        scoped = _task_inventory(inv, t)
        index = _verify_index(scoped)
        index.update(active_probe=active_probe, probe_targets=probe_targets, attempts=attempts)
        ok, detail = _eval_predicate(t, t["acceptance"], index, scoped)
        status = "pass" if ok else "fail"
        if not ok and ("deferred" in detail.lower() or "unknown" in detail.lower()):
            status = "deferred"
        if not ok and ("manual" in detail.lower() or t["type"] == "investigate-asset"):
            status = "manual"
        if ok:
            problem = _evidence_problem(t, inv)
            if problem:
                ok, status, detail = False, "deferred", f"deferred: {problem}"
        if blockers and ok:
            ok, status, detail = False, "deferred", "deferred: prerequisite not accepted: " + ", ".join(blockers)
        visiting.remove(tid)
        result = {"id": tid, "type": t["type"], "acceptance": t["acceptance"],
                  "passed": ok, "status": status, "detail": detail,
                  "target_locations": t.get("target_locations", [])}
        evaluated[tid] = result
        return result

    for t in plan_doc["tasks"]:
        if phase is None or t["phase"] == phase:
            results.append(evaluate(t))
    passed = sum(r["passed"] for r in results)
    # A target task can pass independently while a new use of that same asset
    # appears elsewhere. Report that drift separately and keep the CLI gate red.
    covered = {}
    for t in plan_doc["tasks"]:
        if t.get("target_asset") and t.get("target_locations"):
            covered.setdefault(t["target_asset"], set()).update(
                (x["collector"], x["path"]) for x in t["target_locations"])
    unplanned, seen = [], set()
    for a in inv.assets:
        if a.asset_id not in covered:
            continue
        for o in a.occurrences:
            if not (o.collector.startswith("source-") or o.collector in ("configs", "certs", "tls")):
                continue
            location = (o.collector, _file_locator(o.collector, o.locator))
            key = (a.asset_id, *location)
            if location not in covered[a.asset_id] and key not in seen:
                seen.add(key)
                unplanned.append({"asset_id": a.asset_id, "display": a.display,
                                  "collector": location[0], "path": location[1]})
    bundle = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "plan_hash": hashlib.sha256(open(plan_path, "rb").read()).hexdigest()[:16],
        "cbom_hash": hashlib.sha256(open(fresh_cbom_path, "rb").read()).hexdigest()[:16],
        "phase": phase, "checked": len(results), "passed": passed,
        "accepted": bool(results) and passed == len(results) and not unplanned,
        "selection_note": None if results else "no tasks selected; no acceptance verdict",
        "unplanned_target_occurrences": unplanned,
        # failed is retained as the backwards-compatible count of all non-passes.
        "failed": len(results) - passed,
        "status_counts": {s: sum(r["status"] == s for r in results)
                          for s in ("pass", "fail", "deferred", "manual")},
        "active_probe": active_probe, "probe_capability": probe_cap,
        "results": results,
    }
    with open(evidence_out, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    return bundle


def _eval_predicate(task, pred, index, inv):
    tls_versions = index["tls_versions"]
    tls_groups = index["tls_groups"]
    literals = index["literals"]
    by_algorithm = index["by_algorithm"]

    loc = None
    if "(" in pred and ")" in pred:
        loc = pred[pred.find("(") + 1: pred.find(")")]
    ttype = task["type"]

    if ttype == "decommission-legacy":
        # Active confirmation: handshake against the endpoint forcing legacy /
        # Shor-broken parameters; pass only if every one is REFUSED.
        if index.get("active_probe") and loc in index.get("probe_targets", {}):
            from .handshake import probe_decommissioned
            host, port = index["probe_targets"][loc]
            r = probe_decommissioned(host, port)
            if r["verdict"] == "pass":
                return True, (f"active: {loc} refused all "
                              f"{len(r['refused'])} probeable legacy/Shor-broken "
                              f"parameter(s)")
            if r["verdict"] == "fail":
                accepted = ", ".join(a["probe"] for a in r["accepted"])
                return False, f"active: {loc} still negotiates {accepted}"
            reason = r["errors"][0] if r["errors"] else "nothing probeable"
            return False, f"deferred (fail-closed): {reason}"
        # passive path: only endpoints carry a live-negotiation predicate; for
        # non-endpoint locators this must NOT pass vacuously.
        if loc not in tls_versions:
            return False, f"deferred: no live TLS evidence for {loc} (fail-closed)"
        vers = tls_versions.get(loc, set())
        legacy = {"1.0", "1.1", "3.0"} & vers
        if legacy:
            return False, f"{loc} negotiates versions {sorted(vers)} (passive)"
        return False, "deferred: passive TLS versions do not prove refusal of legacy suites; use an active probe"

    if ttype == "enable-hybrid-kex":
        # Prefer an active handshake when probing is enabled and the endpoint
        # is an authorised target; otherwise fall back to passive observation.
        if index.get("active_probe") and loc in index.get("probe_targets", {}):
            from .handshake import probe_pq_hybrid
            host, port = index["probe_targets"][loc]
            r = probe_pq_hybrid(host, port, attempts=index.get("attempts", 5))
            if r["verdict"] == "pass":
                return True, (f"active handshake: {r['successes']}/{r['attempts']} "
                              f"succeeded on {r['negotiated_group']} "
                              f"(rate {r['success_rate']})")
            if r["verdict"] == "deferred":
                # local stack cannot force PQ groups -> cannot confirm here
                reason = (r["capability"].get("reason")
                          or (r["errors"][0] if r["errors"] else "unknown"))
                return False, f"deferred (fail-closed): {reason}"
            return False, (f"active handshake failed: {r['successes']}/{r['attempts']} "
                           f"succeeded (rate {r['success_rate']}); "
                           f"{r['errors'][0] if r['errors'] else ''}")
        # passive path (no active probe requested / not a live endpoint)
        groups = tls_groups.get(loc, set())
        has_pq = any("hybrid" in g or "ml-kem" in g for g in groups)
        if has_pq:
            return False, f"deferred: passive PQ group observation does not establish handshake success rate at {loc}; use an active probe"
        if index.get("active_probe"):
            return False, f"deferred: no authorised active target or PQ evidence at {loc}"
        return has_pq, f"{loc} key-agreement groups {sorted(groups)} (passive)"

    if ttype == "externalise-algorithm":
        still = (task["target_display"] in literals or
                 _algorithm_of(task) in index.get("literal_algorithms", set()))
        if still:
            return False, "hard-coded literal still present"
        if _algorithm_of(task) in index.get("uncertain_literals", set()):
            return False, "deferred: indeterminate algorithm use remains"
        return True, "literal removed within the task scope"

    if ttype == "replace-algorithm":
        return _check_parameters(task, by_algorithm)

    if ttype == "increase-parameters":
        return _check_parameters(task, by_algorithm)

    if ttype == "deploy-and-revoke":
        return False, "manual confirmation required: inventory absence does not prove deployment or revocation"

    if ttype == "reissue-certificate":
        return _check_reissue(task, index["weak_cert"], inv)

    if ttype == "investigate-asset":
        return False, "investigation task — requires manual disposition"

    return False, "manual disposition required"


def _algorithm_of(task) -> str:
    """Canonical algorithm token for the task's target. Prefers the explicit
    target_algorithm field; falls back to parsing the display string for plans
    produced before that field existed."""
    if task.get("target_algorithm"):
        return task["target_algorithm"].lower()
    disp = task["target_display"]
    return disp.split(" ")[0].split("/")[0].lower()


def _check_parameters(task, by_algorithm):
    """increase-parameters is satisfied when the weakened asset family no
    longer appears below the required strength in the freshly collected CBOM.

    Two requirement forms are supported, taken verbatim from the rule pack:
      * require_min_key_length: N  — no remaining occurrence of the algorithm
        may have a key_length below N (occurrences with unknown key_length are
        treated as failing, i.e. fail-closed).
      * require_algorithm: [...]   — the weak algorithm must be gone entirely,
        replaced by one of the listed acceptable algorithms.
    """
    req = task.get("requirement") or {}
    alg = _algorithm_of(task)
    entries = by_algorithm.get(alg, [])

    if "require_min_key_length" in req:
        floor = int(req["require_min_key_length"])
        offenders = []
        for e in entries:
            kl = e["key_length"]
            if kl is None:
                offenders.append(f"{e['display']} (key length unknown)")
            elif kl < floor:
                offenders.append(f"{e['display']} @ {kl}")
        if offenders:
            return False, f"still below {floor}-bit: " + "; ".join(offenders)
        if not entries:
            return True, f"no remaining {alg.upper()} occurrences at all"
        return True, f"all {len(entries)} {alg.upper()} occurrence(s) meet >= {floor} bits"

    if "require_algorithm" in req:
        allowed = {a.lower() for a in req["require_algorithm"]}
        # weak algorithm still present at all?
        if entries:
            return False, f"weak {alg.upper()} still present ({len(entries)} occurrence(s))"
        present_alts = [a for a in allowed if by_algorithm.get(a)]
        if present_alts:
            floor = req.get("replacement_min_key_length")
            if floor is not None:
                for alt in present_alts:
                    for e in by_algorithm[alt]:
                        if e["key_length"] is None or e["key_length"] < floor:
                            return False, "replacement key length is unknown or below the required floor"
            return True, f"{alg.upper()} replaced; found allowed alternative: {', '.join(sorted(present_alts))}"
        return False, f"{alg.upper()} gone but no acceptable replacement observed"

    # requirement missing from the task (older plan) — do not pass vacuously
    return False, "no machine-checkable requirement attached to task (fail-closed)"

def _check_reissue(task, weak_cert, inv=None):
    """Check the declared target against observed replacement certificates.

    This confirms file-level certificate hygiene, never issuance history,
    live deployment or revocation. Unsupported requirements remain manual.
    """
    req = task.get("requirement") or {}
    if inv is None or not inv.certificates:
        return False, "deferred: no parsed certificate evidence in the task scope"
    for cert in inv.certificates:
        key = inv._assets.get(cert.key_ref)
        sig = inv._assets.get(cert.sig_ref)
        if "min_key_length" in req:
            floor = int(req["min_key_length"])
            if key is None or key.key_length is None:
                return False, "deferred: certificate key length unknown"
            if key.key_length < floor:
                return False, f"certificate key remains below {floor} bits"
        elif "require_signature_hash" in req:
            # Ordered digest families supported by the shipped hygiene policy.
            bits = {"sha2-224": 224, "sha2-256": 256, "sha2-384": 384,
                    "sha2-512": 512, "sha3-256": 256, "sha3-384": 384,
                    "sha3-512": 512, "sha1": 160, "md5": 128}
            target = bits.get(req["require_signature_hash"])
            digest = sig.params.removeprefix("cert-sig:") if sig else ""
            if target is None or digest not in bits:
                return False, "deferred: certificate signature digest cannot be checked against this policy"
            if digest in ("sha1", "md5") or bits[digest] < target:
                return False, "certificate signature digest remains below the requirement"
        elif "prefer" in req:
            floor = int(req.get("min_curve_bits", 256))
            if req["prefer"] != "secp256r1":
                return False, "manual confirmation required: unsupported certificate replacement profile"
            if key is None or key.algorithm != "ecdsa" or key.key_length is None:
                return False, "deferred: certificate EC key parameters unknown"
            if key.key_length < floor:
                return False, f"certificate curve remains below {floor} bits"
        else:
            return False, "manual confirmation required: no supported certificate reissue requirement"
    return True, "target certificate file meets the declared hygiene requirement; deployment and revocation are not checked"


# ---------------- migration progress report ----------------
def timeline_report(points, deltas, summary, svg, out_html: str) -> None:
    """A standalone HTML migration-progress report for management: the trend
    chart, the headline numbers, and the between-scan deltas. Static file."""
    trend_colour = {"improving": "#548235", "worsening": "#C00000",
                    "flat": "#BF9000"}.get(summary.get("trend"), "#666")
    delta_rows = "".join(
        f"<tr><td>{html.escape(d['from'])}</td><td>{html.escape(d['to'])}</td>"
        f"<td style='color:{'#548235' if d['urgent_delta'] < 0 else '#C00000' if d['urgent_delta'] > 0 else '#666'};"
        f"font-weight:700'>{d['urgent_delta']:+d}</td>"
        f"<td>{d['assets_remediated']}</td><td>{d['assets_introduced']}</td></tr>"
        for d in deltas)
    scan_rows = "".join(
        f"<tr><td>{html.escape(p.timestamp[:10] or p.label)}</td>"
        f"<td>{html.escape(p.label)}</td><td>{p.total}</td>"
        f"<td style='font-weight:700'>{p.urgent}</td>"
        f"<td>{p.quantum_broken}</td></tr>"
        for p in points)
    change = summary.get("urgent_change", 0)
    change_str = f"{change:+d}" if change else "0"
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>QRAMP migration progress</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#222}}
h1{{color:#1F3864}} h2{{color:#1F3864;font-size:1.1rem;margin-top:1.8rem}}
.headline{{display:flex;gap:2rem;margin:1rem 0}}
.hnum{{font-size:2rem;font-weight:700;color:#1F3864}}
.hlbl{{font-size:.8rem;color:#666}}
.trend{{font-weight:700;color:{trend_colour};text-transform:capitalize}}
.chart{{border:1px solid #E2E8F0;border-radius:8px;padding:1rem;margin-top:1rem;max-width:720px}}
table{{border-collapse:collapse;margin-top:.8rem;font-size:.9rem}}
th,td{{border:1px solid #B4C7E7;padding:.35rem .6rem;text-align:left}}
th{{background:#D9E2F3}}
.meta{{color:#666;font-size:.85rem;margin-top:1.5rem}}</style></head><body>
<h1>QRAMP — migration progress</h1>
<p>{summary.get('scans', 0)} scans from {html.escape(summary.get('from', ''))}
to {html.escape(summary.get('to', ''))} · trend: <span class="trend">{summary.get('trend', '')}</span></p>
<div class="headline">
  <div><div class="hnum">{summary.get('urgent_last', 0)}</div>
    <div class="hlbl">urgent assets now (was {summary.get('urgent_first', 0)}, {change_str})</div></div>
  <div><div class="hnum">{summary.get('net_remediated', 0)}</div>
    <div class="hlbl">net assets remediated</div></div>
  <div><div class="hnum">{summary.get('quantum_broken_last', 0)}</div>
    <div class="hlbl">quantum-broken now (was {summary.get('quantum_broken_first', 0)})</div></div>
</div>
<h2>Trend</h2>
<div class="chart">{svg}</div>
<h2>Between-scan progress</h2>
<table><thead><tr><th>From</th><th>To</th><th>Urgent Δ</th>
<th>Remediated</th><th>Introduced</th></tr></thead><tbody>{delta_rows}</tbody></table>
<h2>Per-scan snapshot</h2>
<table><thead><tr><th>Date</th><th>Scan</th><th>Total</th>
<th>Urgent (P0+P1)</th><th>Quantum-broken</th></tr></thead><tbody>{scan_rows}</tbody></table>
<p class="meta">Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} · static file, no server required.</p>
</body></html>"""
    open(out_html, "w", encoding="utf-8").write(doc)
