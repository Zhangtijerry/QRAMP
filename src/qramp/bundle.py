# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.bundle — assemble a shareable static report site from an assessed CBOM.

QRAMP produces several artefacts — an interactive dashboard, a migration-progress
report, the dependency and trust-chain graphs, and machine-readable CBOM/SARIF —
but a stakeholder wants one thing to open, not a folder of loose files to piece
together. `bundle` writes a self-contained static site: an `index.html` landing
page with the headline numbers and links to every artefact, the dashboard and
progress report as their own pages, the graphs as both rendered pages and
downloadable DOT/Mermaid text, and the data exports under `data/`. No server, no
external assets — the whole directory can be zipped and handed to management or an
auditor.

Every artefact reuses the existing generators (the dashboard, the timeline
report, the graph exporters, the CycloneDX and SARIF serialisers), so the bundle
is a composition, not a reimplementation, and stays consistent with what the
individual commands produce.
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone

from .model import Inventory


def _summary(inv) -> dict:
    tiers: dict = {}
    exposures: dict = {}
    for a in inv.assets:
        tiers[a.tier or "—"] = tiers.get(a.tier or "—", 0) + 1
        e = a.exposure_class or "unknown"
        exposures[e] = exposures.get(e, 0) + 1
    urgent = tiers.get("P0", 0) + tiers.get("P1", 0)
    return {
        "assets": len(inv.assets),
        "occurrences": inv.occurrence_count(),
        "components": len(inv.components),
        "certificates": len(inv.certificates),
        "tiers": tiers,
        "exposures": exposures,
        "urgent": urgent,
        "quantum_broken": exposures.get("quantum_broken", 0),
        "generated": inv.meta.get("generated", ""),
    }


def _readiness_summary(inv, provider_map):
    try:
        from .readiness import readiness_report
        return readiness_report(inv, provider_map)
    except Exception:
        return None


def build_bundle(cbom_path: str, out_dir: str, *, provider_map: dict | None = None,
                 vex_doc: dict | None = None, history: list | None = None,
                 rules_doc: dict | None = None, title: str = "QRAMP report") -> dict:
    """Write the full static report site to `out_dir`. Returns a manifest of the
    files written."""
    os.makedirs(out_dir, exist_ok=True)
    data_dir = os.path.join(out_dir, "data")
    graphs_dir = os.path.join(out_dir, "graphs")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(graphs_dir, exist_ok=True)

    inv = Inventory.load(cbom_path)
    if provider_map is None:
        import yaml
        pm_path = os.path.join(os.path.dirname(__file__), "data", "provider-map.yaml")
        provider_map = yaml.safe_load(open(pm_path, encoding="utf-8"))

    written = {"pages": [], "graphs": [], "data": []}

    # --- dashboard ---
    from . import report as R
    dash = os.path.join(out_dir, "dashboard.html")
    R.dashboard(cbom_path, dash, provider_map=provider_map, vex_doc=vex_doc,
                history=history)
    written["pages"].append("dashboard.html")

    # --- progress report (only if history supplied) ---
    have_progress = False
    if history:
        try:
            from .timeline import build, summarise, deltas, _point
            from .svggraph import timeline_svg
            points = build(list(history))
            cur = _point(inv, "current")
            points = [p for p in points if p.label != "current"]
            points.append(cur)
            points.sort(key=lambda p: (p.timestamp or "", p.label))
            if len(points) >= 2:
                present = {t for p in points for t, c in p.tiers.items()
                           if c and t in ("P0", "P1", "P2", "P3")}
                series = tuple(t for t in ("P0", "P1", "P2", "P3") if t in present) \
                    or ("P0", "P1")
                svg = timeline_svg(points, series=series)
                prog = os.path.join(out_dir, "progress.html")
                R.timeline_report(points, deltas(points), summarise(points), svg, prog)
                written["pages"].append("progress.html")
                have_progress = True
        except Exception:
            pass

    # --- graph exports (rendered page + downloadable DOT/Mermaid) ---
    from .graphexport import export as gexport
    for which in ("dependency", "chain"):
        for fmt, ext in (("dot", "dot"), ("mermaid", "mmd")):
            try:
                text = gexport(inv, which, fmt)
            except Exception:
                continue
            fn = f"{which}.{ext}"
            open(os.path.join(graphs_dir, fn), "w", encoding="utf-8").write(text + "\n")
            written["graphs"].append(f"graphs/{fn}")

    # --- machine-readable data exports ---
    try:
        from .cyclonedx import to_cyclonedx
        cdx = to_cyclonedx(inv)
        with open(os.path.join(data_dir, "cbom.cdx.json"), "w", encoding="utf-8") as f:
            json.dump(cdx, f, indent=2, ensure_ascii=False)
        written["data"].append("data/cbom.cdx.json")
    except Exception:
        pass
    try:
        from .sarif import to_sarif
        if vex_doc:
            from . import vex as _vex
            _vex.apply(inv, _vex.parse(vex_doc))
        sarif = to_sarif(inv, rules_doc or {})
        with open(os.path.join(data_dir, "findings.sarif"), "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
        written["data"].append("data/findings.sarif")
    except Exception:
        pass

    # --- summary JSON (for programmatic consumers of the bundle) ---
    summ = _summary(inv)
    readiness = _readiness_summary(inv, provider_map)
    with open(os.path.join(data_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump({"summary": summ, "readiness": readiness}, f, indent=2,
                  ensure_ascii=False)
    written["data"].append("data/summary.json")

    # --- provenance page + JSON: which governing standards back the findings,
    #     and how SBOM-discovered components trace back to their packages ---
    have_provenance = False
    prov_rows = _provenance_rows(inv, rules_doc)
    alias_res = _alias_resolutions(inv)
    if prov_rows or alias_res:
        try:
            with open(os.path.join(data_dir, "provenance.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"version": (rules_doc or {}).get("version"),
                           "rules": prov_rows,
                           "alias_resolutions": alias_res}, f, indent=2,
                          ensure_ascii=False)
            written["data"].append("data/provenance.json")
            prov_html = _render_provenance(title, rules_doc, prov_rows, summ,
                                           alias_res)
            open(os.path.join(out_dir, "provenance.html"), "w",
                 encoding="utf-8").write(prov_html)
            written["pages"].append("provenance.html")
            have_provenance = True
        except Exception:
            pass

    # --- index landing page ---
    index_html = _render_index(title, summ, readiness, written, have_progress,
                               have_provenance)
    open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8").write(index_html)
    written["index"] = "index.html"

    return written


def _provenance_rows(inv, rules_doc) -> list:
    """The rules that actually fired in this CBOM, each with its class, rationale,
    occurrence count, and governing-standard citations — the audit-relevant
    subset. Falls back to the asset-carried references when no rule pack is given
    (so a bundle built from a CBOM alone still documents its provenance)."""
    # count occurrences per fired rule id
    counts: dict = {}
    for a in inv.assets:
        if a.rule_id:
            counts[a.rule_id] = counts.get(a.rule_id, 0) + len(a.occurrences)
    if not counts:
        return []

    rows = []
    if rules_doc and rules_doc.get("rules"):
        by_id = {r.get("id"): r for r in rules_doc["rules"]}
        for rid, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            r = by_id.get(rid, {})
            rows.append({
                "id": rid, "class": r.get("class"), "why": r.get("why"),
                "occurrences": n, "references": r.get("references") or [],
            })
    else:
        # no rule pack: reconstruct from what each asset carries
        seen = {}
        for a in inv.assets:
            if not a.rule_id:
                continue
            e = seen.setdefault(a.rule_id, {
                "id": a.rule_id, "class": a.exposure_class, "why": a.rationale,
                "occurrences": 0, "references": a.references or []})
            e["occurrences"] += len(a.occurrences)
        rows = sorted(seen.values(), key=lambda r: -r["occurrences"])
    return rows


def _alias_resolutions(inv) -> list:
    """The package -> component alias resolutions recorded by the manifest
    collector, de-duplicated across manifests. Documents how each SBOM-discovered
    component traces back to the package name it was found under, and whether that
    package is a wrapper (so its version does not drive capability resolution)."""
    seen = {}
    for c in inv.meta.get("collectors", []):
        if c.get("name") != "manifests":
            continue
        for r in c.get("alias_resolutions", []):
            key = (r.get("package"), r.get("version"), r.get("ecosystem"))
            if key not in seen:
                seen[key] = r
    # mapped resolutions first, then unmapped; within each, wrappers grouped last
    return sorted(seen.values(),
                  key=lambda r: (not r.get("mapped"), r.get("wrapper", False),
                                 r.get("component") or "", r.get("package") or ""))


_TIER_COLOUR = {"P0": "#C00000", "P1": "#C55A11", "P2": "#BF9000",
                "P3": "#548235", "OK": "#2F5597", "—": "#808080"}


def _render_index(title, summ, readiness, written, have_progress,
                  have_provenance=False) -> str:
    chips = " ".join(
        f"<span class='chip' style='background:{_TIER_COLOUR.get(t, '#808080')}'>"
        f"{html.escape(str(t))}: {c}</span>"
        for t, c in sorted(summ["tiers"].items(), key=lambda x: str(x[0])))

    ready_block = ""
    if readiness and readiness.get("pqc_migration_assets"):
        pct = readiness["readiness_pct"]
        bar = "#548235" if pct >= 66 else "#BF9000" if pct >= 33 else "#C00000"
        ups = readiness.get("recommended_upgrades", [])
        up_line = ""
        if ups:
            o = ups[0]
            up_line = (f"<p class='muted'>Top upgrade: <b>{html.escape(o['component'])}</b> "
                       f"{html.escape(o['upgrade'])} — unblocks {o['unblocks']} asset(s)</p>")
        ready_block = f"""<div class="card">
  <h3>Migration readiness</h3>
  <div class="big" style="color:{bar}">{pct}%</div>
  <p class="muted">{readiness['already_migratable']}/{readiness['pqc_migration_assets']}
  PQC-migration assets already migratable · {readiness['migration_blocked']} blocked</p>
  <div class="bar"><div style="width:{max(pct, 2):.0f}%;background:{bar}"></div></div>
  {up_line}
</div>"""

    # artefact links
    def link(href, label, note):
        return (f"<li><a href='{html.escape(href)}'>{html.escape(label)}</a>"
                f" <span class='muted'>— {html.escape(note)}</span></li>")

    page_links = [link("dashboard.html", "Interactive dashboard",
                       "inventory table, dependency & trust-chain graphs, readiness, "
                       "upgrade simulation")]
    if have_progress:
        page_links.append(link("progress.html", "Migration progress report",
                               "trend of P0/P1 assets across scans"))
    if have_provenance:
        page_links.append(link("provenance.html", "Provenance & standards",
                               "every finding traced to its governing FIPS/NIST/RFC "
                               "standard, and each discovered component to its package"))
    graph_links = "".join(link(g, os.path.basename(g),
                               "Graphviz DOT" if g.endswith(".dot") else "Mermaid")
                          for g in written["graphs"])
    data_links = "".join(link(d, os.path.basename(d),
                              {"cbom.cdx.json": "CycloneDX CBOM",
                               "findings.sarif": "SARIF findings",
                               "provenance.json": "rule → standard citations",
                               "summary.json": "summary metrics"}.get(
                                  os.path.basename(d), "data"))
                         for d in written["data"])

    generated = summ.get("generated") or datetime.now(timezone.utc).isoformat(timespec="seconds")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title)}</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;color:#1a2332;background:#F4F6FB}}
header{{background:#1F3864;color:#fff;padding:2rem 2.5rem}}
header h1{{margin:0 0 .3rem}} header .sub{{opacity:.85;font-size:.9rem}}
main{{max-width:1000px;margin:0 auto;padding:1.5rem 2.5rem}}
.chip{{color:#fff;padding:.2rem .6rem;border-radius:1rem;margin-right:.4rem;font-size:.85rem}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin:1.2rem 0}}
.card{{background:#fff;border:1px solid #E2E8F0;border-radius:10px;padding:1.1rem 1.3rem;flex:1;min-width:200px}}
.card h3{{margin:0 0 .5rem;color:#1F3864;font-size:1rem}}
.big{{font-size:2.2rem;font-weight:800;line-height:1}}
.muted{{color:#667085;font-size:.85rem;margin:.3rem 0 0}}
.bar{{background:#e6e6e6;border-radius:6px;height:10px;margin-top:.5rem;overflow:hidden}}
.bar>div{{height:10px;border-radius:6px}}
h2{{color:#1F3864;font-size:1.15rem;margin-top:1.8rem}}
ul.arts{{list-style:none;padding:0}} ul.arts li{{padding:.5rem .8rem;background:#fff;border:1px solid #E2E8F0;border-radius:8px;margin:.4rem 0}}
ul.arts a{{color:#1F3864;font-weight:600;text-decoration:none}} ul.arts a:hover{{text-decoration:underline}}
footer{{color:#98a2b3;font-size:.8rem;padding:1.5rem 2.5rem;max-width:1000px;margin:0 auto}}
</style></head><body>
<header>
  <h1>{html.escape(title)}</h1>
  <div class="sub">Post-quantum cryptography posture · scan generated {html.escape(generated)}</div>
</header>
<main>
  <p>{chips}</p>
  <div class="cards">
    <div class="card"><h3>Urgent assets (P0+P1)</h3>
      <div class="big" style="color:#C00000">{summ['urgent']}</div>
      <p class="muted">{summ['quantum_broken']} quantum-broken · {summ['assets']} assets total</p></div>
    <div class="card"><h3>Inventory</h3>
      <div class="big">{summ['assets']}</div>
      <p class="muted">{summ['occurrences']} occurrences · {summ['components']} libraries ·
      {summ['certificates']} certificates</p></div>
    {ready_block}
  </div>

  <h2>Reports</h2>
  <ul class="arts">{''.join(page_links)}</ul>

  <h2>Graphs (for docs &amp; wikis)</h2>
  <ul class="arts">{graph_links}</ul>

  <h2>Machine-readable data</h2>
  <ul class="arts">{data_links}</ul>
</main>
<footer>Generated by QRAMP · {now} · self-contained static site, no server required.</footer>
</body></html>"""


_CLASS_ORDER = ["quantum_broken", "quantum_weakened", "hybrid", "pq_ready", "unknown"]
_CLASS_LABEL = {"quantum_broken": "Quantum-broken", "quantum_weakened": "Quantum-weakened",
                "hybrid": "Hybrid (transitional)", "pq_ready": "PQ-ready",
                "unknown": "Unclassified"}
_CLASS_COLOUR = {"quantum_broken": "#C00000", "quantum_weakened": "#BF9000",
                 "hybrid": "#2F5597", "pq_ready": "#548235", "unknown": "#808080"}


def _fmt_reference(ref) -> str:
    """A single citation as safe HTML, linking the standard id when a URL is given."""
    if not isinstance(ref, dict):
        return html.escape(str(ref))
    std = ref.get("standard", "")
    sec = ref.get("section")
    note = ref.get("note")
    label = html.escape(std + (f" {sec}" if sec else ""))
    url = ref.get("url")
    core = (f"<a href='{html.escape(url)}' target='_blank' rel='noopener'>{label}</a>"
            if url else f"<b>{label}</b>")
    if note:
        core += f" <span class='muted'>({html.escape(note)})</span>"
    return core


def _render_provenance(title, rules_doc, rows, summ, alias_res=None) -> str:
    version = (rules_doc or {}).get("version", "")
    # group fired rules by exposure class, preserving the class ordering
    by_class: dict = {}
    for r in rows:
        by_class.setdefault(r.get("class") or "unknown", []).append(r)

    sections = []
    for cls in _CLASS_ORDER:
        group = by_class.get(cls)
        if not group:
            continue
        colour = _CLASS_COLOUR.get(cls, "#808080")
        body = ""
        for r in group:
            cites = "; ".join(_fmt_reference(x) for x in r.get("references") or []) \
                or "<span class='muted'>—</span>"
            why = html.escape(r.get("why") or "")
            body += (f"<tr><td><code>{html.escape(r.get('id') or '')}</code></td>"
                     f"<td class='num'>{r.get('occurrences', 0)}</td>"
                     f"<td>{why}</td><td>{cites}</td></tr>")
        sections.append(f"""<h2 style="color:{colour}">
  <span class="dot" style="background:{colour}"></span>{_CLASS_LABEL.get(cls, cls)}
  <span class="muted">({len(group)} rule{'s' if len(group) != 1 else ''})</span></h2>
<table><thead><tr><th>Rule</th><th class="num">Occurrences</th>
<th>Rationale</th><th>Governing standards</th></tr></thead><tbody>{body}</tbody></table>""")

    # alias-resolution section: how SBOM-discovered components trace to packages
    alias_section = ""
    if alias_res:
        n_wrap = sum(1 for r in alias_res if r.get("wrapper"))
        n_unmapped = sum(1 for r in alias_res if not r.get("mapped"))
        arows = ""
        for r in alias_res:
            pkg = html.escape(f"{r.get('package', '')}@{r.get('version', '')}")
            eco = html.escape(r.get("ecosystem") or "")
            if r.get("mapped"):
                comp = f"<code>{html.escape(r.get('component') or '')}</code>"
            else:
                comp = ("<span class='muted'>— (no provider-map entry; "
                        "capabilities not attributed)</span>")
            if not r.get("mapped"):
                kind = "<span class='muted'>unmapped</span>"
            elif r.get("wrapper"):
                kind = ("<span title='version does not track the underlying "
                        "library; version-gated capabilities withheld'>"
                        "wrapper ⚠</span>")
            else:
                kind = "direct"
            arows += (f"<tr><td><code>{pkg}</code></td><td>{eco}</td>"
                      f"<td>{comp}</td><td>{kind}</td></tr>")
        alias_section = f"""<h2 style="color:#1F3864">
  <span class="dot" style="background:#1F3864"></span>SBOM discovery — package → component
  <span class="muted">({len(alias_res)} package{'s' if len(alias_res) != 1 else ''};
  {n_wrap} wrapper{'s' if n_wrap != 1 else ''}, {n_unmapped} unmapped)</span></h2>
<p class="lead">Components discovered from package manifests are attributed to a
cryptographic library through the versioned alias map. This table records that
resolution so a component's capabilities are traceable to the exact package it was
found under. A <b>wrapper</b> package's version does not track the underlying
library, so its version-gated capabilities are deliberately withheld
(fail-closed); an <b>unmapped</b> package has no provider-map entry, so no
capabilities are attributed to it.</p>
<table><thead><tr><th>Package</th><th>Ecosystem</th><th>Component</th>
<th>Resolution</th></tr></thead><tbody>{arows}</tbody></table>"""

    n_rules = len(rows)
    n_refs = sum(len(r.get("references") or []) for r in rows)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ver_line = f" · rule pack <code>{html.escape(version)}</code>" if version else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title)} — Provenance</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;color:#1a2332;background:#F4F6FB}}
header{{background:#1F3864;color:#fff;padding:1.6rem 2.5rem}}
header h1{{margin:0 0 .2rem;font-size:1.4rem}} header .sub{{opacity:.85;font-size:.85rem}}
main{{max-width:1000px;margin:0 auto;padding:1.2rem 2.5rem}}
p.lead{{color:#475569}}
a.back{{color:#1F3864;text-decoration:none;font-size:.85rem}} a.back:hover{{text-decoration:underline}}
h2{{font-size:1.05rem;margin-top:1.8rem;display:flex;align-items:center;gap:.5rem}}
.dot{{display:inline-block;width:11px;height:11px;border-radius:50%}}
.muted{{color:#98a2b3;font-weight:400;font-size:.85rem}}
table{{border-collapse:collapse;width:100%;margin-top:.5rem;font-size:.88rem;background:#fff}}
th,td{{border:1px solid #E2E8F0;padding:.45rem .6rem;text-align:left;vertical-align:top}}
th{{background:#F1F5FB;color:#1F3864}}
td.num,th.num{{text-align:right;width:5rem}}
code{{background:#F1F5F9;padding:.05rem .3rem;border-radius:4px}}
a{{color:#1F3864}}
footer{{color:#98a2b3;font-size:.8rem;padding:1.5rem 2.5rem;max-width:1000px;margin:0 auto}}
</style></head><body>
<header>
  <h1>{html.escape(title)} — Provenance &amp; standards</h1>
  <div class="sub">Every finding in this scan traced to the governing standard{ver_line}</div>
</header>
<main>
  <p><a class="back" href="index.html">&larr; back to report index</a></p>
  <p class="lead">{n_rules} classification rule(s) fired across {summ.get('assets', 0)}
  assets, backed by {n_refs} standard citation(s). Each rule below shows the
  cryptographic rationale and the FIPS / NIST SP / RFC / CVE reference that
  justifies the classification, so an auditor can trace any finding to its
  authority.</p>
  {''.join(sections)}
  {alias_section}
</main>
<footer>Generated by QRAMP · {now} · citations are drawn from the rule pack's
<code>references</code> field. Self-contained static page, no server required.</footer>
</body></html>"""
