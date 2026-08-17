# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.graphexport — export QRAMP's two graphs as Graphviz DOT and Mermaid text.

The dashboard renders the dependency graph and the certificate trust chains as
inline SVG for a self-contained page. This module emits the same two graphs as
plain-text Graphviz DOT and Mermaid, so they can be embedded in Markdown docs, a
wiki, or a design record, re-laid-out by external tooling (Graphviz's own engines
handle large graphs far better than the dashboard's fixed columns), or diffed in
version control.

Both exporters read the same model accessors the SVG renderers use — the
`provides` edges for the dependency graph and the `signed_by` edges for the trust
chains — so the text output is the same graph, only in a different notation.
Nodes keep the stable identity used everywhere else (asset_id, component key,
cert bom_ref) so a node in the DOT/Mermaid output maps back to the inventory.
Exposure and weakness colouring carries across as DOT fill colours and Mermaid
classDefs, and the certificate weakest-link is highlighted in both.
"""
from __future__ import annotations

import hashlib
import re

# exposure -> fill colour, matching the SVG renderer
_EXPOSURE_COLOUR = {
    "quantum_broken": "#C00000",
    "quantum_weakened": "#BF9000",
    "pq_ready": "#548235",
    "hybrid": "#2F5597",
    "unknown": "#808080",
    None: "#808080",
}
_LIB_COLOUR = "#1F3864"
_WEAK_COLOUR = "#C00000"
_WARN_COLOUR = "#BF9000"
_OK_COLOUR = "#548235"
_BLOCKING_TAGS = {"weak-signature", "weak-key", "weak-curve", "expired"}


def _nid(prefix: str, raw: str) -> str:
    """A stable, syntactically safe node id for DOT/Mermaid from any raw string."""
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}_{h}"


def _dot_esc(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def _dot_label(*parts: str) -> str:
    """Join label lines with a DOT newline, escaping each part's content first
    so a backslash in the content does not turn into a spurious line break."""
    return "\\n".join(_dot_esc(p) for p in parts if p != "")


def _mermaid_esc(s: str) -> str:
    # Mermaid node labels are quoted; escape quotes and strip characters that
    # break the parser even inside quotes.
    return str(s).replace('"', "'").replace("\n", " ")


def _text_colour(fill: str) -> str:
    """Black or white label depending on how dark the fill is."""
    fill = fill.lstrip("#")
    r, g, b = int(fill[0:2], 16), int(fill[2:4], 16), int(fill[4:6], 16)
    return "#000000" if (r * 299 + g * 587 + b * 114) / 1000 > 140 else "#FFFFFF"


# --------------------------------------------------------------------------
# dependency graph
# --------------------------------------------------------------------------
def dependency_dot(inv) -> str:
    """The library -> capability dependency graph as Graphviz DOT."""
    comps = inv.components
    lines = ["digraph qramp_dependencies {",
             "  rankdir=LR;",
             '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
             '  edge [color="#B4C7E7"];']
    if not comps:
        lines.append('  empty [label="no SBOM components", '
                     'style=filled, fillcolor="#EEEEEE"];')
        lines.append("}")
        return "\n".join(lines)

    # libraries on the left rank
    lines.append("  { rank=same;")
    for c in comps:
        cid = _nid("lib", "|".join(str(k) for k in c.key))
        label = c.display
        lines.append(f'    {cid} [label="{_dot_esc(label)}", '
                     f'fillcolor="{_LIB_COLOUR}", fontcolor="#FFFFFF"];')
    lines.append("  }")

    # capability nodes + provides edges
    seen = set()
    for c in comps:
        cid = _nid("lib", "|".join(str(k) for k in c.key))
        for a in inv.assets_provided_by(c):
            aid = _nid("cap", a.asset_id)
            if a.asset_id not in seen:
                seen.add(a.asset_id)
                fill = _EXPOSURE_COLOUR.get(a.exposure_class, "#808080")
                shared = len(inv.providers_of(a)) > 1
                lbl = _dot_label(a.display, "(shared)" if shared else "")
                lines.append(f'  {aid} [label="{lbl}", '
                             f'fillcolor="{fill}", fontcolor="{_text_colour(fill)}"];')
            # edge: thicker + coloured if this capability has multiple providers
            shared = len(inv.providers_of(a)) > 1
            attrs = ' [color="#1F3864", penwidth=2]' if shared else ""
            lines.append(f"  {cid} -> {aid}{attrs};")
    lines.append("}")
    return "\n".join(lines)


def dependency_mermaid(inv) -> str:
    """The library -> capability dependency graph as Mermaid flowchart."""
    comps = inv.components
    lines = ["flowchart LR"]
    if not comps:
        lines.append('  empty["no SBOM components"]')
        return "\n".join(lines)

    classdefs = {
        "lib": f"fill:{_LIB_COLOUR},color:#fff",
        "quantum_broken": f"fill:{_EXPOSURE_COLOUR['quantum_broken']},color:#fff",
        "quantum_weakened": f"fill:{_EXPOSURE_COLOUR['quantum_weakened']},color:#fff",
        "pq_ready": f"fill:{_EXPOSURE_COLOUR['pq_ready']},color:#fff",
        "hybrid": f"fill:{_EXPOSURE_COLOUR['hybrid']},color:#fff",
        "unknown": f"fill:{_EXPOSURE_COLOUR['unknown']},color:#fff",
    }
    node_class: dict = {}
    seen = set()
    for c in comps:
        cid = _nid("lib", "|".join(str(k) for k in c.key))
        lines.append(f'  {cid}["{_mermaid_esc(c.display)}"]')
        node_class[cid] = "lib"
        for a in inv.assets_provided_by(c):
            aid = _nid("cap", a.asset_id)
            if a.asset_id not in seen:
                seen.add(a.asset_id)
                shared = len(inv.providers_of(a)) > 1
                lbl = a.display + (" (shared)" if shared else "")
                lines.append(f'  {aid}["{_mermaid_esc(lbl)}"]')
                cls = a.exposure_class if a.exposure_class in classdefs else "unknown"
                node_class[aid] = cls
            shared = len(inv.providers_of(a)) > 1
            arrow = " ==>" if shared else " -->"
            lines.append(f"  {cid}{arrow} {aid}")
    # class definitions and assignments
    for name, style in classdefs.items():
        lines.append(f"  classDef {name} {style}")
    # group nodes by class for compact assignment
    by_class: dict = {}
    for nid, cls in node_class.items():
        by_class.setdefault(cls, []).append(nid)
    for cls, nids in by_class.items():
        lines.append(f"  class {','.join(nids)} {cls}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# certificate trust chains
# --------------------------------------------------------------------------
def _cert_class(weak_tags) -> str:
    if weak_tags & _BLOCKING_TAGS:
        return "weak"
    if weak_tags:
        return "warn"
    return "ok"


def _chains(inv):
    certs = inv.certificates
    if not certs:
        return []
    inv.link_chain()
    leaves = [c for c in certs if not c.is_ca]
    roots_shown = leaves or certs
    return [inv.chain_of(l) for l in roots_shown]


def chain_dot(inv) -> str:
    """Certificate trust chains (leaf -> issuer -> root) as Graphviz DOT."""
    lines = ["digraph qramp_trust_chains {",
             "  rankdir=LR;",
             '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
             '  edge [color="#888888"];']
    chains = _chains(inv)
    if not chains:
        lines.append('  empty [label="no certificates", '
                     'style=filled, fillcolor="#EEEEEE"];')
        lines.append("}")
        return "\n".join(lines)

    _colour = {"weak": _WEAK_COLOUR, "warn": _WARN_COLOUR, "ok": _OK_COLOUR}
    emitted = set()
    edges = set()
    for chain in chains:
        if not chain:
            continue
        wl = inv.weakest_link(chain[0])
        broken_by = wl.get("chain_broken_by")
        for cert in chain:
            nid = _nid("cert", cert.bom_ref)
            if cert.bom_ref not in emitted:
                emitted.add(cert.bom_ref)
                cls = _cert_class(cert.weak_tags)
                fill = _colour[cls]
                role = "CA" if cert.is_ca else "leaf"
                tags = ", ".join(sorted(cert.weak_tags)) if cert.weak_tags else ""
                is_weakest = broken_by and cert.display == broken_by
                lbl = _dot_label(cert.display, role, tags)
                extra = ', penwidth=3, color="#000000"' if is_weakest else ""
                lines.append(f'  {nid} [label="{lbl}", '
                             f'fillcolor="{fill}", fontcolor="{_text_colour(fill)}"{extra}];')
        # signed_by edges (leaf -> issuer)
        for cert in chain:
            if cert.signed_by:
                child = _nid("cert", cert.bom_ref)
                parent = _nid("cert", cert.signed_by)
                if (child, parent) not in edges:
                    edges.add((child, parent))
                    lines.append(f"  {child} -> {parent} [label=\"signed by\"];")
    lines.append("}")
    return "\n".join(lines)


def chain_mermaid(inv) -> str:
    """Certificate trust chains as a Mermaid flowchart."""
    lines = ["flowchart LR"]
    chains = _chains(inv)
    if not chains:
        lines.append('  empty["no certificates"]')
        return "\n".join(lines)

    classdefs = {
        "weak": f"fill:{_WEAK_COLOUR},color:#fff",
        "warn": f"fill:{_WARN_COLOUR},color:#fff",
        "ok": f"fill:{_OK_COLOUR},color:#fff",
        "weakest": f"fill:{_WEAK_COLOUR},color:#fff,stroke:#000,stroke-width:3px",
    }
    node_class: dict = {}
    emitted = set()
    edges = set()
    for chain in chains:
        if not chain:
            continue
        wl = inv.weakest_link(chain[0])
        broken_by = wl.get("chain_broken_by")
        for cert in chain:
            nid = _nid("cert", cert.bom_ref)
            if cert.bom_ref not in emitted:
                emitted.add(cert.bom_ref)
                role = "CA" if cert.is_ca else "leaf"
                tags = (" — " + ", ".join(sorted(cert.weak_tags))) if cert.weak_tags else ""
                lines.append(f'  {nid}["{_mermaid_esc(cert.display)}<br/>{role}{tags}"]')
                is_weakest = broken_by and cert.display == broken_by
                node_class[nid] = "weakest" if is_weakest else _cert_class(cert.weak_tags)
        for cert in chain:
            if cert.signed_by:
                child = _nid("cert", cert.bom_ref)
                parent = _nid("cert", cert.signed_by)
                if (child, parent) not in edges:
                    edges.add((child, parent))
                    lines.append(f"  {child} -->|signed by| {parent}")
    for name, style in classdefs.items():
        lines.append(f"  classDef {name} {style}")
    by_class: dict = {}
    for nid, cls in node_class.items():
        by_class.setdefault(cls, []).append(nid)
    for cls, nids in by_class.items():
        lines.append(f"  class {','.join(nids)} {cls}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------
def export(inv, graph: str, fmt: str) -> str:
    """graph in {'dependency','chain'}, fmt in {'dot','mermaid'}."""
    table = {
        ("dependency", "dot"): dependency_dot,
        ("dependency", "mermaid"): dependency_mermaid,
        ("chain", "dot"): chain_dot,
        ("chain", "mermaid"): chain_mermaid,
    }
    fn = table.get((graph, fmt))
    if fn is None:
        raise ValueError(f"unknown graph/format: {graph!r}/{fmt!r}")
    return fn(inv)
