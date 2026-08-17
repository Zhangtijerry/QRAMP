# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.orgdash — roll many repositories' PQC posture up into one static,
self-contained HTML dashboard for an organisation.

Each repo's CI emits a compact *repo card* (`repo_card`) — a small JSON of the
metrics and gate outcomes it already computes. A central job collects the cards
(committed to a repo, or downloaded as artifacts) and `render_dashboard` turns the
directory into a single sortable page: which repos are red, how much quantum-broken
crypto is out there, and how migration readiness is distributed across the org.

The page follows the same rules as the report bundle — one file, no server, inline
vanilla JS, no external libraries — so it can be published to Pages or handed to a
CISO as-is.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

CARD_SCHEMA = "qramp-repo-card-1"

_CLASS_COLOUR = {"quantum_broken": "#C00000", "quantum_weakened": "#BF9000",
                 "pq_ready": "#2E7D32", "hybrid": "#1565C0", "unknown": "#808080"}


def repo_card(inv, *, name: str, provider_map: dict | None = None,
              gates: dict | None = None, url: str | None = None) -> dict:
    """Build the compact per-repo posture card from an assessed inventory and,
    optionally, its CI gate outcomes (the {gate: outcome|{outcome,url}} mapping)."""
    tiers: dict = {}
    exposures: dict = {}
    for a in inv.assets:
        tiers[a.tier or "—"] = tiers.get(a.tier or "—", 0) + 1
        e = a.exposure_class or "unknown"
        exposures[e] = exposures.get(e, 0) + 1
    urgent = tiers.get("P0", 0) + tiers.get("P1", 0)

    readiness_pct = None
    if provider_map is not None:
        try:
            from .readiness import readiness_report
            rd = readiness_report(inv, provider_map)
            if rd.get("pqc_migration_assets"):
                readiness_pct = rd["readiness_pct"]
        except Exception:
            readiness_pct = None

    gate_summary = None
    if gates:
        def _outcome(v):
            return v.get("outcome") if isinstance(v, dict) else v
        failing = [n for n, v in gates.items() if _outcome(v) == "failure"]
        gate_summary = {"failed": len(failing), "total": len(gates),
                        "failing": failing}

    return {
        "schema": CARD_SCHEMA,
        "repo": name,
        "generated": inv.meta.get("generated") or
                     datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "url": url,
        "metrics": {
            "assets": len(inv.assets),
            "urgent": urgent,
            "quantum_broken": exposures.get("quantum_broken", 0),
            "quantum_weakened": exposures.get("quantum_weakened", 0),
            "readiness_pct": readiness_pct,
        },
        "gates": gate_summary,
    }


def load_cards(paths: list) -> list:
    """Load repo cards from a list of file paths or directories. Silently skips
    files that are not valid repo cards so a stray file does not break the roll-up."""
    import os
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(os.path.join(p, f) for f in os.listdir(p)
                                if f.endswith(".json")))
        else:
            files.append(p)
    cards = []
    for f in files:
        try:
            doc = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("schema") == CARD_SCHEMA:
            cards.append(doc)
    return cards


def aggregate(cards: list) -> dict:
    """Org-level roll-up across repo cards."""
    repos = len(cards)
    total_urgent = sum(c["metrics"].get("urgent", 0) for c in cards)
    total_broken = sum(c["metrics"].get("quantum_broken", 0) for c in cards)
    total_weakened = sum(c["metrics"].get("quantum_weakened", 0) for c in cards)
    gate_fail_repos = sum(1 for c in cards
                          if (c.get("gates") or {}).get("failed", 0) > 0)
    urgent_repos = sum(1 for c in cards if c["metrics"].get("urgent", 0) > 0)
    readies = [c["metrics"]["readiness_pct"] for c in cards
               if c["metrics"].get("readiness_pct") is not None]
    median_readiness = None
    if readies:
        s = sorted(readies)
        n = len(s)
        median_readiness = (s[n // 2] if n % 2 else round((s[n // 2 - 1] + s[n // 2]) / 2, 1))
    return {
        "repos": repos,
        "total_urgent": total_urgent,
        "total_broken": total_broken,
        "total_weakened": total_weakened,
        "gate_fail_repos": gate_fail_repos,
        "urgent_repos": urgent_repos,
        "median_readiness": median_readiness,
        "clean_repos": repos - urgent_repos - gate_fail_repos
                       if repos >= urgent_repos + gate_fail_repos else 0,
    }


def _readiness_band(pct):
    if pct is None:
        return ("n/a", "#808080")
    if pct >= 75:
        return (f"{pct}%", "#2E7D32")
    if pct >= 40:
        return (f"{pct}%", "#BF9000")
    return (f"{pct}%", "#C00000")


def _rank(card):
    """Sort key: worst first — failing gates, then urgent, then broken."""
    g = (card.get("gates") or {}).get("failed", 0)
    m = card["metrics"]
    return (-(1 if g else 0), -m.get("urgent", 0), -m.get("quantum_broken", 0),
            card.get("repo", ""))


def render_dashboard(cards: list, *, title: str = "PQC migration — organisation") -> str:
    """Render the aggregated dashboard as a single self-contained HTML page."""
    agg = aggregate(cards)
    cards = sorted(cards, key=_rank)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # org-level stat cards
    def stat(label, value, colour="var(--fg)"):
        return (f'<div class="stat"><div class="stat-v" style="color:{colour}">'
                f'{value}</div><div class="stat-l">{label}</div></div>')

    med = agg["median_readiness"]
    med_txt = f"{med}%" if med is not None else "n/a"
    stats = "".join([
        stat("repositories", agg["repos"]),
        stat("repos with failing gates", agg["gate_fail_repos"],
             "#C00000" if agg["gate_fail_repos"] else "#2E7D32"),
        stat("repos with urgent assets", agg["urgent_repos"],
             "#C00000" if agg["urgent_repos"] else "#2E7D32"),
        stat("total urgent (P0+P1)", agg["total_urgent"],
             "#C00000" if agg["total_urgent"] else "#2E7D32"),
        stat("total quantum-broken", agg["total_broken"],
             _CLASS_COLOUR["quantum_broken"] if agg["total_broken"] else "#2E7D32"),
        stat("median readiness", med_txt),
    ])

    # repo rows
    rows = []
    for c in cards:
        m = c["metrics"]
        g = c.get("gates") or {}
        gate_cell = "<span class='muted'>—</span>"
        if c.get("gates"):
            if g.get("failed", 0):
                tip = html.escape(", ".join(g.get("failing", [])))
                gate_cell = (f"<span style='color:#C00000' title='{tip}'>"
                             f"❌ {g['failed']}/{g['total']} failed</span>")
            else:
                gate_cell = f"<span style='color:#2E7D32'>✅ {g['total']} passed</span>"
        r_txt, r_col = _readiness_band(m.get("readiness_pct"))
        repo = html.escape(c.get("repo", "?"))
        repo_cell = (f"<a href='{html.escape(c['url'])}'>{repo}</a>"
                     if c.get("url") else repo)
        urgent = m.get("urgent", 0)
        broken = m.get("quantum_broken", 0)
        weak = m.get("quantum_weakened", 0)
        gen = html.escape((c.get("generated") or "")[:10])
        # data-* attributes drive client-side sorting
        rows.append(
            f"<tr data-repo='{repo}' data-urgent='{urgent}' data-broken='{broken}' "
            f"data-weakened='{weak}' data-assets='{m.get('assets', 0)}' "
            f"data-scan='{gen}' "
            f"data-readiness='{m.get('readiness_pct') if m.get('readiness_pct') is not None else -1}' "
            f"data-gatefail='{g.get('failed', 0)}'>"
            f"<td>{repo_cell}</td>"
            f"<td class='num' style='color:{'#C00000' if urgent else 'inherit'}'>{urgent}</td>"
            f"<td class='num' style='color:{_CLASS_COLOUR['quantum_broken'] if broken else 'inherit'}'>{broken}</td>"
            f"<td class='num'>{weak}</td>"
            f"<td class='num'>{m.get('assets', 0)}</td>"
            f"<td class='num' style='color:{r_col}'>{r_txt}</td>"
            f"<td>{gate_cell}</td>"
            f"<td class='muted'>{gen}</td></tr>")

    empty = "<p class='muted'>No repo cards found.</p>" if not cards else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{ --fg:#1a1a1a; --muted:#6b7280; --line:#e5e7eb; --bg:#ffffff; }}
  * {{ box-sizing:border-box; }}
  body {{ font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; color:var(--fg);
         margin:0; padding:2rem; background:var(--bg); }}
  h1 {{ font-size:1.5rem; margin:0 0 .25rem; }}
  .lead {{ color:var(--muted); margin:0 0 1.5rem; }}
  .stats {{ display:flex; flex-wrap:wrap; gap:1rem; margin-bottom:1.5rem; }}
  .stat {{ border:1px solid var(--line); border-radius:8px; padding:.75rem 1rem;
           min-width:150px; }}
  .stat-v {{ font-size:1.6rem; font-weight:650; }}
  .stat-l {{ color:var(--muted); font-size:.8rem; }}
  table {{ border-collapse:collapse; width:100%; }}
  th, td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--line); }}
  th {{ font-size:.8rem; color:var(--muted); cursor:pointer; user-select:none;
        white-space:nowrap; }}
  th:hover {{ color:var(--fg); }}
  td.num, th.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .muted {{ color:var(--muted); }}
  a {{ color:#1565C0; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
  footer {{ color:var(--muted); font-size:.8rem; margin-top:2rem; }}
</style></head><body>
  <h1>{html.escape(title)}</h1>
  <p class="lead">Post-quantum posture across {agg['repos']} repository(ies),
  worst first. Click a column to re-sort.</p>
  <div class="stats">{stats}</div>
  {empty}
  <table id="repos"><thead><tr>
    <th data-k="repo" data-t="s">Repository</th>
    <th class="num" data-k="urgent">Urgent</th>
    <th class="num" data-k="broken">Q-broken</th>
    <th class="num" data-k="weakened">Weakened</th>
    <th class="num" data-k="assets">Assets</th>
    <th class="num" data-k="readiness">Readiness</th>
    <th data-k="gatefail">Gates</th>
    <th data-k="scan" data-t="s">Last scan</th>
  </tr></thead><tbody>{''.join(rows)}</tbody></table>
  <footer>Generated by QRAMP · {now} · self-contained static page, no server required.</footer>
  <script>
    (function() {{
      var table = document.getElementById('repos');
      if (!table) return;
      var tbody = table.querySelector('tbody');
      var dir = {{}};
      table.querySelectorAll('th').forEach(function(th) {{
        th.addEventListener('click', function() {{
          var k = th.getAttribute('data-k');
          var isStr = th.getAttribute('data-t') === 's';
          dir[k] = !dir[k];
          var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
          rows.sort(function(a, b) {{
            var av = a.getAttribute('data-' + k), bv = b.getAttribute('data-' + k);
            if (!isStr) {{ av = parseFloat(av); bv = parseFloat(bv); }}
            if (av < bv) return dir[k] ? -1 : 1;
            if (av > bv) return dir[k] ? 1 : -1;
            return 0;
          }});
          rows.forEach(function(r) {{ tbody.appendChild(r); }});
        }});
      }});
    }})();
  </script>
</body></html>"""
