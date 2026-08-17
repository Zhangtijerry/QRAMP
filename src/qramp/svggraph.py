# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.svggraph — deterministic, dependency-free SVG rendering of QRAMP's two
graphs for the static HTML dashboard.

No physics simulation, no JS, no external libraries: nodes are placed on fixed
columns and edges are drawn as cubic Béziers, so the output is reproducible and
embeds directly in a static file. Two renderers:

  * dependency_svg  — library → capability bipartite graph (provides edges),
    capabilities coloured by exposure, shared capabilities marked.
  * chain_svg       — certificate trust chains (signed_by edges), nodes
    coloured by weakness, the weakest link per chain highlighted.
"""
from __future__ import annotations

import html

# exposure -> fill colour (red / amber / green / blue / grey)
EXPOSURE_COLOUR = {
    "quantum_broken": "#C00000",
    "quantum_weakened": "#BF9000",
    "pq_ready": "#548235",
    "hybrid": "#2F5597",
    "unknown": "#808080",
    None: "#808080",
}
WEAK_COLOUR = "#C00000"       # a cert carrying a chain-invalidating weakness
WARN_COLOUR = "#BF9000"       # a cert with a non-blocking weakness (e.g. expiring)
OK_COLOUR = "#548235"
LIB_COLOUR = "#1F3864"


def _esc(s: str) -> str:
    return html.escape(str(s))


def _text(x, y, s, *, size=12, fill="#222", anchor="start", weight="400"):
    return (f'<text x="{x:.0f}" y="{y:.0f}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}" '
            f'font-family="-apple-system,Segoe UI,Roboto,sans-serif">{_esc(s)}</text>')


def _edge(x1, y1, x2, y2, *, colour="#B4C7E7", width=1.5, dash=""):
    """A left-to-right cubic Bézier between two anchor points."""
    mx = (x1 + x2) / 2
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<path d="M{x1:.0f},{y1:.0f} C{mx:.0f},{y1:.0f} {mx:.0f},{y2:.0f} '
            f'{x2:.0f},{y2:.0f}" fill="none" stroke="{colour}" '
            f'stroke-width="{width}"{d}/>')


def _node_box(x, y, w, h, label, *, fill, sub="", rx=6, stroke="#fff",
              text_fill="#fff", data_asset="", node_class=""):
    attrs = ""
    if data_asset:
        attrs += f' data-asset="{_esc(data_asset)}"'
    if node_class:
        attrs += f' class="{_esc(node_class)}"'
    parts = [f'<g{attrs}>'] if attrs else ['<g>']
    parts.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" '
                 f'rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
    cy = y + (h / 2) + (4 if not sub else -2)
    parts.append(_text(x + w / 2, cy, label, size=12, fill=text_fill,
                       anchor="middle", weight="600"))
    if sub:
        parts.append(_text(x + w / 2, y + h / 2 + 12, sub, size=10,
                           fill=text_fill, anchor="middle"))
    parts.append("</g>")
    return "".join(parts)


def _legend(x, y, items):
    out = [_text(x, y - 8, "Legend", size=11, fill="#666", weight="600")]
    for i, (colour, label) in enumerate(items):
        yy = y + i * 18
        out.append(f'<rect x="{x}" y="{yy}" width="12" height="12" rx="2" fill="{colour}"/>')
        out.append(_text(x + 18, yy + 10, label, size=11, fill="#444"))
    return "".join(out)


def dependency_svg(inv) -> str:
    """Bipartite library → capability graph. Returns an <svg> string, or an
    empty-state note if there are no components."""
    comps = inv.components
    if not comps:
        return ('<p style="color:#888">No SBOM components — scan with '
                '<code>--sbom</code> to populate the dependency graph.</p>')

    # collect the capability assets that are actually provided
    provided_keys = []
    seen = set()
    for c in comps:
        for a in inv.assets_provided_by(c):
            if a.key not in seen:
                seen.add(a.key)
                provided_keys.append(a)
    provided_keys.sort(key=lambda a: (a.exposure_class or "z", a.display))

    row_h = 34
    pad_top = 70
    n_rows = max(len(comps), len(provided_keys))
    height = pad_top + n_rows * row_h + 40
    width = 780
    lib_x, lib_w = 30, 200
    cap_x, cap_w = 540, 210

    # y position per node
    lib_y = {c.key: pad_top + i * row_h for i, c in enumerate(comps)}
    cap_y = {a.key: pad_top + i * row_h for i, a in enumerate(provided_keys)}

    parts = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
             f'style="max-width:100%;height:auto">']
    parts.append(_text(lib_x, 40, "Libraries", size=13, fill="#666", weight="700"))
    parts.append(_text(cap_x, 40, "Cryptographic capabilities", size=13, fill="#666", weight="700"))

    # edges first (under nodes)
    for c in comps:
        y1 = lib_y[c.key] + 14
        for a in inv.assets_provided_by(c):
            y2 = cap_y[a.key] + 14
            shared = len(inv.providers_of(a)) > 1
            parts.append(_edge(lib_x + lib_w, y1, cap_x, y2,
                               colour="#9DC3E6" if shared else "#D6DCE5",
                               width=2.2 if shared else 1.3))

    # library nodes
    for c in comps:
        y = lib_y[c.key]
        parts.append(_node_box(lib_x, y, lib_w, 28, c.name, sub=f"v{c.version}",
                               fill=LIB_COLOUR))

    # capability nodes
    for a in provided_keys:
        y = cap_y[a.key]
        colour = EXPOSURE_COLOUR.get(a.exposure_class, "#808080")
        providers = inv.providers_of(a)
        sub = ("shared × %d" % len(providers)) if len(providers) > 1 else (a.exposure_class or "")
        parts.append(_node_box(cap_x, y, cap_w, 28, a.display.split(" [")[0],
                               sub=sub, fill=colour, data_asset=a.asset_id,
                               node_class="qramp-cap"))

    parts.append(_legend(cap_x + cap_w + 8, pad_top + 6, [
        (EXPOSURE_COLOUR["quantum_broken"], "quantum-broken"),
        (EXPOSURE_COLOUR["quantum_weakened"], "quantum-weakened"),
        (EXPOSURE_COLOUR["pq_ready"], "PQ-ready"),
        ("#9DC3E6", "shared capability"),
    ]))
    parts.append("</svg>")
    return "".join(parts)


# --- certificate chains ---------------------------------------------------
_BLOCKING = {"weak-signature", "weak-key", "weak-curve", "expired"}


def _cert_colour(weak_tags) -> str:
    if _BLOCKING & set(weak_tags):
        return WEAK_COLOUR
    if weak_tags:
        return WARN_COLOUR
    return OK_COLOUR


def chain_svg(inv) -> str:
    """Certificate trust chains as left-to-right trees (leaf → CA → root).
    Highlights the weakest link. Returns an <svg> string or an empty note."""
    certs = inv.certificates
    if not certs:
        return ('<p style="color:#888">No certificate nodes — scan with '
                '<code>--certs</code> to populate the trust chain.</p>')
    inv.link_chain()

    leaves = [c for c in certs if not c.is_ca]
    # a self-signed root with no leaf still deserves a row
    orphans = [c for c in certs if c.is_ca and
               not any(l.signed_by == c.bom_ref for l in certs)]
    roots_shown = leaves or certs

    node_w, node_h = 210, 34
    col_gap = 90
    row_gap = 20
    pad_top, pad_left = 60, 30

    # each leaf produces a horizontal chain (row). compute rows.
    chains = [inv.chain_of(l) for l in roots_shown]
    max_depth = max((len(ch) for ch in chains), default=1)
    width = pad_left + max_depth * (node_w + col_gap) + 40
    height = pad_top + len(chains) * (node_h + row_gap) + 40

    parts = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
             f'style="max-width:100%;height:auto">']
    parts.append(_text(pad_left, 36, "Certificate trust chains  (leaf → issuer → root)",
                       size=13, fill="#666", weight="700"))

    for r, chain in enumerate(chains):
        y = pad_top + r * (node_h + row_gap)
        wl = inv.weakest_link(chain[0]) if chain else {"chain_broken_by": None}
        broken_by = wl.get("chain_broken_by")
        prev_anchor = None
        for depth, cert in enumerate(chain):
            x = pad_left + depth * (node_w + col_gap)
            colour = _cert_colour(cert.weak_tags)
            # edge from previous (leaf) to this (issuer)
            if prev_anchor is not None:
                px, py = prev_anchor
                parts.append(_edge(px, py, x, y + node_h / 2,
                                   colour="#C9C9C9", width=1.6, dash="4,3"))
            role = "CA" if cert.is_ca else "leaf"
            # subject can be long; trim
            subj = cert.subject.replace("CN=", "")
            sub = role + (" · " + ", ".join(sorted(cert.weak_tags)) if cert.weak_tags else "")
            is_weakest = broken_by and cert.display == broken_by
            stroke = "#000" if is_weakest else "#fff"
            parts.append(_node_box(x, y, node_w, node_h, subj[:26], sub=sub[:34],
                                   fill=colour, stroke=stroke))
            if is_weakest:
                parts.append(_text(x + node_w / 2, y - 4, "weakest link",
                                   size=10, fill=WEAK_COLOUR, anchor="middle", weight="700"))
            prev_anchor = (x + node_w, y + node_h / 2)

    parts.append(_legend(pad_left, height - 30, [
        (WEAK_COLOUR, "chain-invalidating weakness"),
        (WARN_COLOUR, "non-blocking (e.g. expiring)"),
        (OK_COLOUR, "clean"),
    ]) if False else "")     # legend inline below instead
    # horizontal legend
    lg_y = height - 24
    parts.append(_text(pad_left, lg_y, "■", size=13, fill=WEAK_COLOUR))
    parts.append(_text(pad_left + 14, lg_y, "chain-invalidating", size=11, fill="#444"))
    parts.append(_text(pad_left + 150, lg_y, "■", size=13, fill=WARN_COLOUR))
    parts.append(_text(pad_left + 164, lg_y, "non-blocking", size=11, fill="#444"))
    parts.append(_text(pad_left + 280, lg_y, "■", size=13, fill=OK_COLOUR))
    parts.append(_text(pad_left + 294, lg_y, "clean", size=11, fill="#444"))
    parts.append("</svg>")
    return "".join(parts)


# tier -> colour for the migration-progress trend chart
TIER_COLOUR = {"P0": "#C00000", "P1": "#C55A11", "P2": "#BF9000",
               "P3": "#548235", "OK": "#2F5597", "—": "#808080"}


def timeline_svg(points, *, series=("P0", "P1"), width=680, height=300) -> str:
    """A deterministic multi-line trend chart of tier counts over time.

    `points` is a list of qramp.timeline.Point. Each named tier in `series` is
    drawn as a line across the scans (X = scan order/time, Y = asset count), so a
    falling P0/P1 line shows migration progress. No physics, no JS: fixed axes,
    straight segments, dots at each scan."""
    if not points:
        return ('<p style="color:#888">No scans — provide two or more assessed '
                'CBOMs to draw a migration trend.</p>')

    pad_l, pad_r, pad_t, pad_b = 48, 120, 24, 56
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(points)

    # y-scale: 0 .. max count across all plotted series (min 1)
    ymax = 1
    for p in points:
        for t in series:
            ymax = max(ymax, p.tiers.get(t, 0))
    # round ymax up to a "nice" gridline
    import math
    step = max(1, math.ceil(ymax / 4))
    ymax = step * 4

    def xpos(i):
        return pad_l + (plot_w * i / (n - 1) if n > 1 else plot_w / 2)

    def ypos(v):
        return pad_t + plot_h - (plot_h * v / ymax)

    parts = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
             f'font-family="-apple-system,Segoe UI,Roboto,sans-serif">']

    # gridlines + y labels
    for g in range(5):
        v = step * g
        y = ypos(v)
        parts.append(f'<line x1="{pad_l}" y1="{y:.0f}" x2="{pad_l + plot_w}" '
                     f'y2="{y:.0f}" stroke="#EEF2F7" stroke-width="1"/>')
        parts.append(_text(pad_l - 8, y + 4, str(v), size=10, fill="#888", anchor="end"))

    # x axis labels (scan date or label)
    for i, p in enumerate(points):
        x = xpos(i)
        lab = (p.timestamp[:10] if p.timestamp else p.label)
        parts.append(_text(x, height - pad_b + 18, lab, size=10, fill="#666",
                           anchor="middle"))

    # one polyline per tier series
    for t in series:
        colour = TIER_COLOUR.get(t, "#333")
        pts_xy = [(xpos(i), ypos(p.tiers.get(t, 0))) for i, p in enumerate(points)]
        d = " ".join(f"{'M' if k == 0 else 'L'}{x:.0f},{y:.0f}"
                     for k, (x, y) in enumerate(pts_xy))
        parts.append(f'<path d="{d}" fill="none" stroke="{colour}" '
                     f'stroke-width="2.5"/>')
        for (x, y), p in zip(pts_xy, points):
            v = p.tiers.get(t, 0)
            parts.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="3.5" fill="{colour}"/>')
            parts.append(_text(x, y - 8, str(v), size=10, fill=colour,
                               anchor="middle", weight="600"))

    # legend on the right
    lg_x = pad_l + plot_w + 20
    for k, t in enumerate(series):
        ly = pad_t + 6 + k * 20
        parts.append(_text(lg_x, ly + 4, "■", size=13, fill=TIER_COLOUR.get(t, "#333")))
        first = points[0].tiers.get(t, 0)
        last = points[-1].tiers.get(t, 0)
        change = last - first
        arrow = "▼" if change < 0 else "▲" if change > 0 else "→"
        parts.append(_text(lg_x + 16, ly + 4,
                           f"{t}: {first}→{last} {arrow}", size=11, fill="#444"))

    # axis title
    parts.append(_text(pad_l, pad_t - 8, "assets", size=10, fill="#888"))
    parts.append("</svg>")
    return "".join(parts)
