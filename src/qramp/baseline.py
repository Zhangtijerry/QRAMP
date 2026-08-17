# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.baseline — accept a pre-existing backlog of exposed crypto so a gate
blocks only *new* regressions, not the migration's starting point.

When a team first turns QRAMP on, a codebase usually already contains a pile of
quantum-broken crypto. A hard gate ("no quantum-broken finding may remain") would
be red on day one and could never be enabled. A baseline records today's exposed
assets as *known and accepted* — like a linter baseline — so the gate passes as
long as nothing new appears. New broken crypto (an asset not in the baseline)
still fails, and as the backlog is migrated the baseline can be regenerated
smaller, ratcheting the acceptance down over time.

This is deliberately separate from VEX: a VEX statement says "we assessed this and
it does not apply / is accepted for a stated reason"; a baseline entry just says
"this is pre-existing work we have not done yet." Both suppress a gate, for
different reasons and with different review expectations.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

# exposure classes a gate cares about, worst first
DEFAULT_EXPOSURES = ("quantum_broken",)


def _failing(inv, exposures) -> list:
    want = set(exposures)
    return [a for a in inv.assets if (a.exposure_class or "") in want]


def generate(inv, exposures=DEFAULT_EXPOSURES) -> dict:
    """Freeze the currently-exposed assets as an accepted backlog."""
    accepted = []
    for a in sorted(_failing(inv, exposures), key=lambda a: a.asset_id):
        accepted.append({
            "asset_id": a.asset_id,
            "display": a.display,
            "exposure_class": a.exposure_class,
            "tier": a.tier,
        })
    return {
        "version": "qramp-baseline-1",
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "exposures": list(exposures),
        "accepted": accepted,
    }


def evaluate(inv, baseline: dict, exposures=None) -> dict:
    """Compare the current inventory against a baseline. Returns the exposed
    assets that are new (not accepted), accepted (in the baseline), and resolved
    (accepted but no longer present — the backlog has shrunk)."""
    exposures = tuple(exposures or baseline.get("exposures") or DEFAULT_EXPOSURES)
    accepted_ids = {e.get("asset_id") for e in baseline.get("accepted", [])}
    accepted_meta = {e.get("asset_id"): e for e in baseline.get("accepted", [])}

    failing = _failing(inv, exposures)
    failing_ids = {a.asset_id for a in failing}

    new = sorted((a for a in failing if a.asset_id not in accepted_ids),
                 key=lambda a: a.asset_id)
    accepted = sorted((a for a in failing if a.asset_id in accepted_ids),
                      key=lambda a: a.asset_id)
    resolved = sorted(accepted_ids - failing_ids)
    return {
        "exposures": list(exposures),
        "new": [{"asset_id": a.asset_id, "display": a.display,
                 "exposure_class": a.exposure_class, "tier": a.tier} for a in new],
        "accepted": [{"asset_id": a.asset_id, "display": a.display} for a in accepted],
        "resolved": [{"asset_id": aid,
                      "display": accepted_meta.get(aid, {}).get("display", aid)}
                     for aid in resolved],
        "new_count": len(new),
        "accepted_count": len(accepted),
        "resolved_count": len(resolved),
    }


@dataclass
class Finding:
    level: str
    asset_id: str
    message: str


def lint(baseline: dict, inv=None) -> list[Finding]:
    """Static-check a baseline: well-formed entries, no duplicates, and — with an
    inventory — flag stale entries whose asset is no longer exposed (the backlog
    shrank, so the baseline should be regenerated smaller)."""
    findings: list[Finding] = []
    accepted = baseline.get("accepted", [])
    if not isinstance(accepted, list):
        findings.append(Finding("error", "-", "'accepted' must be a list"))
        return findings
    seen: set = set()
    for i, e in enumerate(accepted):
        aid = e.get("asset_id") if isinstance(e, dict) else None
        if not aid:
            findings.append(Finding("error", f"<entry #{i}>",
                                    "entry is missing 'asset_id'"))
            continue
        if aid in seen:
            findings.append(Finding("error", aid, "duplicate asset_id"))
        seen.add(aid)
    if inv is not None:
        ev = evaluate(inv, baseline)
        for r in ev["resolved"]:
            findings.append(Finding("warning", r["asset_id"],
                f"accepted asset {r['display']} is no longer exposed; regenerate "
                f"the baseline to drop it (ratchet the acceptance down)"))
    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.level])
    return findings
