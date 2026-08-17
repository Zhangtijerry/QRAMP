# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.prcomment — a compact Markdown summary of a scan for a pull-request
comment, so the post-quantum posture shows up in code review without anyone
opening the full report.

The comment leads with the headline numbers a reviewer cares about — urgent
(P0/P1) assets, quantum-broken count, migration readiness — and, when historical
CBOMs are supplied, the trend since the last scan (did this change make things
better or worse?). It stays deliberately small: a table, a one-line trend, and a
top upgrade recommendation, with a hidden marker so a CI job can find and update
its own previous comment instead of posting a new one each push.
"""
from __future__ import annotations

from .model import Inventory

# a stable hidden marker so a CI step can locate and update its prior comment
MARKER = "<!-- qramp-pr-comment -->"

_TREND_ICON = {"improving": "🟢", "worsening": "🔴", "flat": "⚪"}

# exposure classes worth calling out in a PR diff, worst first
_DIFF_CLASSES = [
    ("quantum_broken", "quantum-broken"),
    ("quantum_weakened", "quantum-weakened"),
]


def _diff_vs_base(inv, base_path):
    """Compare the current inventory against a base-branch CBOM and report, per
    exposure class, which assets this change adds or removes (by stable asset
    key). Returns None if the base cannot be read."""
    try:
        base = Inventory.load(base_path)
    except Exception:
        return None
    cur = {a.key: a for a in inv.assets}
    old = {a.key: a for a in base.assets}
    added_keys = cur.keys() - old.keys()
    removed_keys = old.keys() - cur.keys()
    added: dict = {}
    removed: dict = {}
    for k in added_keys:
        e = cur[k].exposure_class or "unknown"
        added.setdefault(e, []).append(cur[k].display)
    for k in removed_keys:
        e = old[k].exposure_class or "unknown"
        removed.setdefault(e, []).append(old[k].display)
    for d in (added, removed):
        for e in d:
            d[e] = sorted(d[e])
    return {"added": added, "removed": removed,
            "base_assets": len(old), "current_assets": len(cur)}


def _fmt_asset_list(names, cap=8):
    """A comma-separated, backticked asset list, truncated with a +N tail."""
    shown = [f"`{n}`" for n in names[:cap]]
    if len(names) > cap:
        shown.append(f"…+{len(names) - cap} more")
    return ", ".join(shown)


def _readiness(inv, provider_map):
    try:
        from .readiness import readiness_report
        return readiness_report(inv, provider_map)
    except Exception:
        return None


def _trend(inv, history):
    """Return the timeline summary treating the current inventory as the latest
    point, or None if there is no usable history."""
    if not history:
        return None
    try:
        from .timeline import build, summarise, _point
        points = build(list(history))
        cur = _point(inv, "current")
        points = [p for p in points if p.label != "current"]
        points.append(cur)
        points.sort(key=lambda p: (p.timestamp or "", p.label))
        if len(points) < 2:
            return None
        return summarise(points)
    except Exception:
        return None


def build_comment(cbom_path: str, *, provider_map: dict | None = None,
                  history: list | None = None, title: str = "QRAMP — PQC posture",
                  report_url: str | None = None, base_cbom: str | None = None,
                  gates: dict | None = None, subtitle: str | None = None,
                  compact: bool = False) -> str:
    """Assemble the PR-comment Markdown for an assessed CBOM.

    `title` and `subtitle` let a team brand the comment (e.g. a company or service
    name). `compact` folds the informational sections (trend, top upgrade) into a
    single collapsible block so the actionable parts — verdict, metrics, the
    change vs base, and any failing gates — stay prominent.
    """
    inv = Inventory.load(cbom_path)
    if provider_map is None:
        import os
        import yaml
        pm = os.path.join(os.path.dirname(__file__), "data", "provider-map.yaml")
        provider_map = yaml.safe_load(open(pm, encoding="utf-8"))

    tiers: dict = {}
    exposures: dict = {}
    for a in inv.assets:
        tiers[a.tier or "—"] = tiers.get(a.tier or "—", 0) + 1
        e = a.exposure_class or "unknown"
        exposures[e] = exposures.get(e, 0) + 1
    urgent = tiers.get("P0", 0) + tiers.get("P1", 0)
    broken = exposures.get("quantum_broken", 0)
    weakened = exposures.get("quantum_weakened", 0)

    rd = _readiness(inv, provider_map)
    trend = _trend(inv, history)
    diff = _diff_vs_base(inv, base_cbom) if base_cbom else None

    # headline verdict emoji
    verdict = "🔴" if urgent else ("🟠" if broken or weakened else "🟢")

    lines = [MARKER, f"### {verdict} {title}"]
    if subtitle:
        lines.append(f"_{subtitle}_")
    lines.append("")

    # headline metrics table
    ready_cell = "—"
    if rd and rd.get("pqc_migration_assets"):
        ready_cell = f"{rd['readiness_pct']}%"
    lines += [
        "| Metric | Value |",
        "| --- | --- |",
        f"| Urgent (P0+P1) | **{urgent}** |",
        f"| Quantum-broken | {broken} |",
        f"| Quantum-weakened | {weakened} |",
        f"| Migration readiness | {ready_cell} |",
        f"| Assets scanned | {len(inv.assets)} |",
        "",
    ]

    # change-vs-base section: the net effect of THIS pull request
    if diff is not None:
        change_lines = []
        score = 0                          # severity-weighted: broken=2, weakened=1
        _WEIGHT = {"quantum_broken": 2, "quantum_weakened": 1}
        _ADD_ICON = {"quantum_broken": "🔴", "quantum_weakened": "🟠"}
        for cls, label in _DIFF_CLASSES:
            added = diff["added"].get(cls, [])
            removed = diff["removed"].get(cls, [])
            score += _WEIGHT[cls] * (len(added) - len(removed))
            if added:
                change_lines.append(
                    f"- {_ADD_ICON[cls]} **+{len(added)} {label}**: "
                    f"{_fmt_asset_list(added)}")
            if removed:
                change_lines.append(
                    f"- 🟢 **−{len(removed)} {label}**: {_fmt_asset_list(removed)}")
        if change_lines:
            # severity-weighted so trading a broken asset for a weakened one
            # (e.g. RSA -> AES-128) reads as an improvement, not a wash
            head = ("⚠️ This PR **worsens** the PQC posture." if score > 0
                    else "✅ This PR **improves** the PQC posture." if score < 0
                    else "➖ This PR shifts assets without a net change in exposure.")
            lines.append(f"**Change vs base branch** — {head}")
            lines += change_lines
            lines.append("")
        else:
            lines.append("**Change vs base branch** — ➖ no change to "
                         "quantum-broken or quantum-weakened assets.")
            lines.append("")

    # informational sections — trend and top upgrade. In compact mode these are
    # folded into one collapsible block so the actionable parts stay prominent.
    secondary = []
    if trend and trend.get("scans", 0) >= 2:
        icon = _TREND_ICON.get(trend["trend"], "⚪")
        change = trend["urgent_change"]
        arrow = "▼" if change < 0 else "▲" if change > 0 else "→"
        change_str = f"{arrow} {abs(change)}" if change else "no change"
        secondary.append(
            f"{icon} **Trend** ({trend['scans']} scans): urgent "
            f"{trend['urgent_first']} → {trend['urgent_last']} ({change_str}); "
            f"{trend['net_remediated']} net assets remediated since first scan.")
    if rd and rd.get("recommended_upgrades"):
        o = rd["recommended_upgrades"][0]
        secondary.append(
            f"💡 **Top upgrade:** `{o['component']}` {o['upgrade']} — "
            f"unblocks {o['unblocks']} asset(s).")

    if secondary and not compact:
        for s in secondary:
            lines.append(s)
            lines.append("")
    elif secondary:                    # compact: fold into one collapsible block
        lines.append("<details>")
        lines.append("<summary><b>Trend &amp; recommendations</b></summary>")
        lines.append("")
        for s in secondary:
            lines.append(s)
            lines.append("")
        lines.append("</details>")
        lines.append("")

    # gate results (a collapsible table) — the CI gate matrix at a glance. Each
    # value is either an outcome string ("success"/"failure"/"skipped") or a
    # mapping {outcome, url}; when a url is present the outcome links to the CI
    # log for that gate, so a failure is one click from its cause.
    if gates:
        _GATE_ICON = {"success": "✅", "failure": "❌", "skipped": "➖"}

        def _outcome(v):
            return v.get("outcome") if isinstance(v, dict) else v

        def _url(v):
            return v.get("url") if isinstance(v, dict) else None

        failed = [n for n, v in gates.items() if _outcome(v) == "failure"]
        summary = (f"❌ {len(failed)} gate(s) failed" if failed
                   else "✅ all gates passed")

        def _cell(v):
            o = _outcome(v)
            label = f"{_GATE_ICON.get(o, '⚠️')} {o}"
            u = _url(v)
            return f"[{label}]({u})" if u and o == "failure" else label

        rows = "\n".join(
            f"| {name} | {_cell(v)} |" for name, v in gates.items())
        # in compact mode keep the gate table open only when something failed
        open_attr = " open" if (failed and compact) else ""
        lines.append(f"<details{open_attr}>")
        lines.append(f"<summary><b>Gate results</b> — {summary}</summary>")
        lines.append("")
        lines.append("| Gate | Result |")
        lines.append("| --- | --- |")
        lines.append(rows)
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if report_url:
        lines.append(f"📄 [Full report]({report_url}) · dashboard, provenance, graphs.")
    else:
        lines.append("📄 Full report is attached to this run as the "
                     "`qramp-report` artifact.")

    return "\n".join(lines).rstrip() + "\n"
