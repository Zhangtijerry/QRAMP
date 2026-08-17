# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.simulate — model the effect of a library upgrade before doing it.

`readiness` ranks the upgrades that would unblock the most risk; `simulate`
answers the next question a team asks — *"if we actually bump OpenSSL to 3.5,
what changes?"* — by recomputing the dependency graph and the migration-blocked
set at the proposed versions and diffing against today.

An upgrade changes two things, and the simulation is careful to keep them
distinct because conflating them would overstate the benefit:

  * **Capability delta** — re-resolving the provider map at the new version may
    add capabilities (OpenSSL 3.5 gains ML-KEM/ML-DSA) or remove them (a 1.0.x
    build stops offering SSLv3). These are concrete changes to what the stack
    ships.
  * **Migration unblocking** — a broken key-agreement/signature asset becomes
    *migratable* once some deployed library provides its PQC replacement. The
    asset is not auto-fixed (the code still has to switch to ML-KEM), but the
    blocker is gone. The simulation reports these as "unblocked", never as
    "resolved".

No inventory is mutated; the simulation works from the provider map and the
current component versions, so it is side-effect free and cheap to run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .providermap import resolve, satisfies
from .readiness import PQ_REPLACEMENT, TIER_WEIGHT, _pq_algorithms


@dataclass
class VersionChange:
    component: str
    from_version: str
    to_version: str
    added: list = field(default_factory=list)      # algorithms newly provided
    removed: list = field(default_factory=list)     # algorithms no longer provided
    invalid: bool = False                           # a downgrade or non-change


def _provided_algs(entry: dict, version: str) -> set:
    return {p.algorithm for p in resolve(entry, version)}


def parse_upgrades(specs: list[str]) -> dict:
    """Parse ['openssl=3.5', 'bouncycastle=1.78'] into {name: version}."""
    out = {}
    for s in specs:
        if "=" not in s:
            raise ValueError(f"upgrade spec {s!r} must be name=version")
        name, ver = s.split("=", 1)
        out[name.strip().lower()] = ver.strip()
    return out


def _pq_coverage(inv, provider_map: dict, overrides: dict) -> set:
    """The set of PQ algorithms the deployment provides, applying version
    overrides for named components."""
    entries = {e["component"].lower(): e for e in provider_map.get("components", [])}
    pq = _pq_algorithms()
    covered = set()
    for c in inv.components:
        entry = entries.get(c.name.lower())
        if entry is None:
            # not mapped; fall back to whatever the graph already recorded
            for a in inv.assets_provided_by(c):
                if a.algorithm in pq:
                    covered.add(a.algorithm)
            continue
        version = overrides.get(c.name.lower(), c.version)
        for alg in _provided_algs(entry, version):
            if alg in pq:
                covered.add(alg)
    return covered


def _blocked_under(inv, coverage: set) -> list:
    """Broken KEM/signature assets whose PQC replacement is NOT in `coverage`."""
    out = []
    for a in inv.assets:
        if a.exposure_class not in ("quantum_broken", "quantum_weakened"):
            continue
        need = PQ_REPLACEMENT.get(a.primitive)
        if need is None:
            continue
        if need not in coverage:
            out.append(a)
    return out


def simulate(inv, provider_map: dict, upgrades: dict) -> dict:
    """Model the effect of upgrading the named components to the given versions.

    upgrades: {component_name: target_version}. Returns a diff describing the
    capability changes, the change in migration-blocked assets, and the tier
    breakdown of what gets unblocked.
    """
    entries = {e["component"].lower(): e for e in provider_map.get("components", [])}
    pq = _pq_algorithms()

    # --- per-component capability delta ---
    changes: list[VersionChange] = []
    applied = {}
    for c in inv.components:
        name = c.name.lower()
        if name not in upgrades:
            continue
        target = upgrades[name]
        entry = entries.get(name)
        vc = VersionChange(component=c.name, from_version=c.version, to_version=target)
        if entry is None:
            vc.invalid = True                       # unmapped component
        elif satisfies(c.version, f">={target}"):
            vc.invalid = True                       # not an upgrade (same/older)
        else:
            before = _provided_algs(entry, c.version)
            after = _provided_algs(entry, target)
            vc.added = sorted(after - before)
            vc.removed = sorted(before - after)
            applied[name] = target
        changes.append(vc)

    # components named in the upgrade but absent from the deployment
    present = {c.name.lower() for c in inv.components}
    unknown = [name for name in upgrades if name not in present]

    # --- migration-blocked before vs after ---
    cov_before = _pq_coverage(inv, provider_map, {})
    cov_after = _pq_coverage(inv, provider_map, applied)
    blocked_before = _blocked_under(inv, cov_before)
    blocked_after = _blocked_under(inv, cov_after)
    before_keys = {a.key for a in blocked_before}
    after_keys = {a.key for a in blocked_after}
    unblocked = [a for a in blocked_before if a.key not in after_keys]

    # --- tier breakdown + weighted risk cleared ---
    by_tier: dict = {}
    weight = 0.0
    for a in unblocked:
        by_tier[a.tier] = by_tier.get(a.tier, 0) + 1
        weight += TIER_WEIGHT.get(a.tier, 0.5)

    # tier distribution of the migration-blocked set, before and after, so a
    # dashboard can animate the shift.
    def tier_dist(assets):
        d: dict = {}
        for a in assets:
            d[a.tier or "—"] = d.get(a.tier or "—", 0) + 1
        return d
    blocked_tier_before = tier_dist(blocked_before)
    blocked_tier_after = tier_dist(blocked_after)

    # newly-provided / newly-removed PQ capabilities across the whole upgrade
    pq_added = sorted({alg for vc in changes for alg in vc.added if alg in pq})
    pq_removed = sorted({alg for vc in changes for alg in vc.removed if alg in pq})

    n_scope = len([a for a in inv.assets
                   if a.exposure_class in ("quantum_broken", "quantum_weakened")
                   and PQ_REPLACEMENT.get(a.primitive) is not None])

    def pct(blocked):
        return round(100.0 * (n_scope - len(blocked)) / n_scope, 1) if n_scope else 100.0

    return {
        "upgrades": {vc.component: f"{vc.from_version} -> {vc.to_version}"
                     for vc in changes if not vc.invalid},
        "invalid_upgrades": [
            {"component": vc.component,
             "reason": ("not mapped in provider map" if vc.component.lower() not in entries
                        else "not an upgrade (target <= current)")}
            for vc in changes if vc.invalid],
        "unknown_components": unknown,
        "capability_changes": [
            {"component": vc.component, "upgrade": f"{vc.from_version} -> {vc.to_version}",
             "added": vc.added, "removed": vc.removed}
            for vc in changes if not vc.invalid and (vc.added or vc.removed)],
        "pq_capabilities_added": pq_added,
        "pq_capabilities_removed": pq_removed,
        "readiness_before_pct": pct(blocked_before),
        "readiness_after_pct": pct(blocked_after),
        "blocked_before": len(blocked_before),
        "blocked_after": len(blocked_after),
        "blocked_tier_before": blocked_tier_before,
        "blocked_tier_after": blocked_tier_after,
        "unblocked": len(unblocked),
        "unblocked_by_tier": by_tier,
        "risk_cleared_weight": round(weight, 1),
        "unblocked_examples": [a.display for a in unblocked[:8]],
    }
