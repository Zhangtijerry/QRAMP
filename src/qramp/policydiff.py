# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.policydiff — audit what a policy change does to a real inventory.

QRAMP has three editable, versioned policy inputs: the rule pack (classification),
the provider map (which library version ships which capability), and VEX (accepted
exceptions). Each has a linter and, for the first two, a snapshot regression on
synthetic fixtures. `policy-diff` is the complementary tool: instead of asking
"is the new policy internally consistent?", it asks "what would the new policy do
to *the assets we actually have*?".

Given a real assessed CBOM and two versions of a policy file, it re-evaluates the
inventory under each and reports the concrete deltas:

  * rule pack     -> assets whose exposure class, firing rule, or Mosca tier
                     changes (a stricter rule that repromotes P2 -> P0, or a new
                     rule that shadows an old one for some real asset).
  * provider map  -> assets whose migration-blocked status flips (a version-gate
                     edit that suddenly attributes ML-KEM to a deployed library,
                     or withdraws it).
  * VEX           -> assets whose suppression status changes (an exception added,
                     removed, or downgraded from not_affected to affected).

The evaluation runs on the CBOM's real assets, so the output is "these N assets
in your codebase change", not an abstract fixture diff. It is side-effect free:
each side is computed on a freshly loaded copy of the inventory.
"""
from __future__ import annotations

import yaml

from .model import Inventory


def _classify_map(cbom_path: str, rules_doc: dict, lifetimes: dict) -> dict:
    """Load the CBOM fresh, classify + tier under `rules_doc`, and return a
    stable {asset_id: {display, class, rule, tier}} map."""
    from . import assess
    inv = Inventory.load(cbom_path)
    assess.classify(inv, rules_doc)
    assess.prioritise(inv, rules_doc, lifetimes)
    out = {}
    for a in inv.assets:
        out[a.asset_id] = {"display": a.display, "class": a.exposure_class,
                           "rule": a.rule_id, "tier": a.tier}
    return out


def diff_rules(cbom_path: str, old_rules: dict, new_rules: dict,
               lifetimes: dict) -> dict:
    """Diff two rule packs against the real inventory. Reports per-asset changes
    in class / firing rule / tier, and the aggregate tier-distribution shift."""
    before = _classify_map(cbom_path, old_rules, lifetimes)
    after = _classify_map(cbom_path, new_rules, lifetimes)

    changed = []
    for aid, aft in after.items():
        bef = before.get(aid)
        if bef is None:
            continue
        if (bef["class"] != aft["class"] or bef["rule"] != aft["rule"]
                or bef["tier"] != aft["tier"]):
            changed.append({
                "asset": aft["display"],
                "class": [bef["class"], aft["class"]],
                "rule": [bef["rule"], aft["rule"]],
                "tier": [bef["tier"], aft["tier"]],
                "severity": _severity(bef["tier"], aft["tier"]),
            })
    # aggregate tier distribution before/after
    def dist(m):
        d = {}
        for v in m.values():
            d[v["tier"]] = d.get(v["tier"], 0) + 1
        return d
    changed.sort(key=lambda c: (-_TIER_RANK.get(c["tier"][1], 0), c["asset"]))
    return {
        "kind": "rules",
        "changed_count": len(changed),
        "changed": changed,
        "tier_before": dist(before),
        "tier_after": dist(after),
        "worsened": sum(1 for c in changed if c["severity"] == "worse"),
        "improved": sum(1 for c in changed if c["severity"] == "better"),
    }


_TIER_RANK = {"P0": 4, "P1": 3, "P2": 2, "P3": 1, "OK": 0, None: 0}


def _severity(old_tier, new_tier) -> str:
    o, n = _TIER_RANK.get(old_tier, 0), _TIER_RANK.get(new_tier, 0)
    if n > o:
        return "worse"       # promoted to a more urgent tier
    if n < o:
        return "better"
    return "lateral"


def diff_provider_map(cbom_path: str, old_map: dict, new_map: dict) -> dict:
    """Diff two provider maps against the real inventory: which assets flip
    migration-blocked status because the map's version gates changed."""
    from .readiness import blocked_assets

    inv_old = Inventory.load(cbom_path)
    inv_new = Inventory.load(cbom_path)
    # re-provide edges under each map so blocked_assets sees the right coverage
    _reprovide(inv_old, old_map)
    _reprovide(inv_new, new_map)
    old_blocked = {a.asset_id for a in blocked_assets(inv_old)}
    new_blocked = {a.asset_id for a in blocked_assets(inv_new)}
    disp = {a.asset_id: a.display for a in inv_new.assets}

    newly_blocked = sorted(new_blocked - old_blocked, key=lambda x: disp.get(x, x))
    newly_unblocked = sorted(old_blocked - new_blocked, key=lambda x: disp.get(x, x))
    return {
        "kind": "provider-map",
        "blocked_before": len(old_blocked),
        "blocked_after": len(new_blocked),
        "newly_blocked": [{"asset": disp.get(x, x)} for x in newly_blocked],
        "newly_unblocked": [{"asset": disp.get(x, x)} for x in newly_unblocked],
    }


def _reprovide(inv, provider_map: dict) -> None:
    """Rewire the component -> capability provides edges of an inventory using
    `provider_map`, so a map edit is reflected without a re-scan. Only affects
    the PQ-coverage view used by blocked_assets; existing assets are reused."""
    from .providermap import resolve
    entries = {e["component"].lower(): e for e in provider_map.get("components", [])}
    # clear existing provides edges
    for c in inv.components:
        c.provides = set()
    for c in inv.components:
        entry = entries.get(c.name.lower())
        if entry is None:
            continue
        for prov in resolve(entry, c.version):
            # find or create the capability asset, then wire the edge
            from .model import Occurrence
            a = inv.observe(prov.primitive, prov.algorithm,
                            Occurrence(collector="policydiff",
                                       locator=f"provider:{c.name}",
                                       evidence="re-provided for policy diff"),
                            params=prov.params, key_length=prov.key_length)
            inv.provide(c, a)


def diff_vex(cbom_path: str, old_vex: dict, new_vex: dict) -> dict:
    """Diff two VEX documents against the real inventory: which assets change
    suppression status."""
    from . import vex

    inv_old = Inventory.load(cbom_path)
    inv_new = Inventory.load(cbom_path)
    vex.apply(inv_old, vex.parse(old_vex or {}))
    vex.apply(inv_new, vex.parse(new_vex or {}))

    def supp_map(inv):
        m = {}
        for a in inv.assets:
            rec = vex.suppression_for(a)
            m[a.asset_id] = (a.display, rec["justification"] if rec else None,
                             bool(rec))
        return m

    before = supp_map(inv_old)
    after = supp_map(inv_new)
    added, removed, changed = [], [], []
    for aid, (disp, just, supp) in after.items():
        b_disp, b_just, b_supp = before.get(aid, (disp, None, False))
        if supp and not b_supp:
            added.append({"asset": disp, "justification": just})
        elif not supp and b_supp:
            removed.append({"asset": disp, "was_justification": b_just})
        elif supp and b_supp and just != b_just:
            changed.append({"asset": disp, "justification": [b_just, just]})
    return {
        "kind": "vex",
        "suppressions_before": sum(1 for _, _, s in before.values() if s),
        "suppressions_after": sum(1 for _, _, s in after.values() if s),
        "added": added, "removed": removed, "changed": changed,
    }


def _load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def policy_diff(cbom_path: str, *, kind: str, old_path: str, new_path: str,
                lifetimes_path: str | None = None) -> dict:
    """Dispatch to the right diff by policy kind ('rules' | 'provider-map' |
    'vex')."""
    old, new = _load(old_path), _load(new_path)
    if kind == "rules":
        lifetimes = _load(lifetimes_path) if lifetimes_path else {"default_years": 3}
        return diff_rules(cbom_path, old, new, lifetimes)
    if kind == "provider-map":
        return diff_provider_map(cbom_path, old, new)
    if kind == "vex":
        return diff_vex(cbom_path, old, new)
    raise ValueError(f"unknown policy kind {kind!r}")
