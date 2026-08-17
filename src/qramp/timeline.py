# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.timeline — track migration progress across a series of scans.

A single CBOM is a snapshot; a migration is a trend. `timeline` reads a series of
assessed CBOMs, orders them by their scan timestamp, and computes the trajectory
of the inventory over time — how the count of P0/P1 assets falls (or rises), how
readiness climbs, how many net assets were remediated between scans — so a team
can show progress and a manager can see the migration's ROI as a curve rather
than a point.

Each CBOM carries its scan time in `metadata.timestamp`, restored on load, so the
series is self-ordering: point QRAMP at a directory of historical CBOMs (or list
them explicitly) and it builds the timeline. The per-scan metrics reuse the same
tier/exposure model as the rest of the tool, and the between-scan deltas reuse
the existing asset-identity diff, so a drop in P0 is attributed to the specific
assets that were remediated.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .model import Inventory

_TIERS = ("P0", "P1", "P2", "P3", "OK")


@dataclass
class Point:
    label: str
    timestamp: str
    total: int
    tiers: dict            # tier -> count
    exposures: dict        # exposure_class -> count
    quantum_broken: int    # convenience: assets that are Shor-broken
    urgent: int            # P0 + P1 count (the headline number)
    asset_ids: set = field(default_factory=set)

    def as_dict(self) -> dict:
        return {"label": self.label, "timestamp": self.timestamp,
                "total": self.total, "tiers": self.tiers,
                "exposures": self.exposures, "quantum_broken": self.quantum_broken,
                "urgent": self.urgent}


def _point(inv: Inventory, label: str) -> Point:
    tiers: dict = {}
    exposures: dict = {}
    qb = 0
    ids = set()
    for a in inv.assets:
        t = a.tier or "—"
        tiers[t] = tiers.get(t, 0) + 1
        e = a.exposure_class or "unknown"
        exposures[e] = exposures.get(e, 0) + 1
        if a.exposure_class == "quantum_broken":
            qb += 1
        ids.add(a.asset_id)
    urgent = tiers.get("P0", 0) + tiers.get("P1", 0)
    return Point(label=label, timestamp=inv.meta.get("generated", ""),
                 total=len(inv.assets), tiers=tiers, exposures=exposures,
                 quantum_broken=qb, urgent=urgent, asset_ids=ids)


def build(cbom_paths: list[str], labels: list[str] | None = None) -> list[Point]:
    """Load each CBOM, build a Point, and return the series ordered by scan
    timestamp (falling back to input order when timestamps tie or are absent)."""
    points = []
    for i, path in enumerate(cbom_paths):
        inv = Inventory.load(path)
        label = labels[i] if labels and i < len(labels) else _default_label(path, i)
        points.append((_point(inv, label), i))
    # stable sort by timestamp, then by original index
    points.sort(key=lambda pi: (pi[0].timestamp or "", pi[1]))
    return [p for p, _ in points]


def _default_label(path: str, i: int) -> str:
    import os
    base = os.path.splitext(os.path.basename(path))[0]
    return base or f"scan {i + 1}"


def deltas(points: list[Point]) -> list[dict]:
    """Between-scan changes: net remediated (assets present before and gone
    now), newly introduced, and the movement in the urgent (P0+P1) count."""
    out = []
    for prev, cur in zip(points, points[1:]):
        remediated = prev.asset_ids - cur.asset_ids
        introduced = cur.asset_ids - prev.asset_ids
        out.append({
            "from": prev.label, "to": cur.label,
            "urgent_delta": cur.urgent - prev.urgent,
            "quantum_broken_delta": cur.quantum_broken - prev.quantum_broken,
            "total_delta": cur.total - prev.total,
            "assets_remediated": len(remediated),
            "assets_introduced": len(introduced),
        })
    return out


def summarise(points: list[Point]) -> dict:
    """Headline trend over the whole series."""
    if not points:
        return {"scans": 0}
    first, last = points[0], points[-1]
    urgent_change = last.urgent - first.urgent
    qb_change = last.quantum_broken - first.quantum_broken
    # net remediated across the whole window (present at start, gone at end)
    ever_remediated = first.asset_ids - last.asset_ids
    return {
        "scans": len(points),
        "from": first.label, "to": last.label,
        "urgent_first": first.urgent, "urgent_last": last.urgent,
        "urgent_change": urgent_change,
        "quantum_broken_first": first.quantum_broken,
        "quantum_broken_last": last.quantum_broken,
        "quantum_broken_change": qb_change,
        "net_remediated": len(ever_remediated),
        "trend": ("improving" if urgent_change < 0 else
                  "worsening" if urgent_change > 0 else "flat"),
    }
