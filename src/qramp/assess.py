# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.assess — Layer 3.

Classification comes from a versioned YAML rule pack; prioritisation applies
Mosca's inequality X + Y − Z per asset, where X is the confidentiality
lifetime of the data the asset protects (policy input), Y the migration time
(fed back from the planner, with per-class defaults before a plan exists) and
Z the assumed CRQC horizon (scenario in the rule pack).
"""
from __future__ import annotations

import hashlib
import json

import yaml

from .model import Inventory, CryptoAsset


def load_rules(path: str) -> dict:
    raw = open(path, "rb").read()
    doc = yaml.safe_load(raw)
    doc["_hash"] = hashlib.sha256(raw).hexdigest()[:16]
    doc["_path"] = path
    return doc


def _match(rule: dict, a: CryptoAsset) -> bool:
    m = rule.get("match", {})
    if "primitive" in m and a.primitive not in _as_list(m["primitive"]):
        return False
    if "algorithm" in m and a.algorithm not in _as_list(m["algorithm"]):
        return False
    if "params" in m and a.params not in _as_list(m["params"]):
        return False
    if "max_key_length" in m and not (a.key_length is not None and a.key_length <= m["max_key_length"]):
        return False
    if "min_key_length" in m and not (a.key_length is not None and a.key_length >= m["min_key_length"]):
        return False
    if "has_tag" in m:
        want = set(_as_list(m["has_tag"]))
        if not (want & a.tag_union()):
            return False
    return True


def _as_list(v):
    return v if isinstance(v, list) else [v]


def classify(inv: Inventory, rules: dict) -> None:
    for a in inv.assets:
        a.exposure_class, a.rationale, a.remediate = "unknown", "no rule matched", None
        a.rule_id = None
        for rule in rules.get("rules", []):
            if _match(rule, a):
                a.exposure_class = rule["class"]
                a.rationale = rule.get("why", rule.get("id", ""))
                a.rule_id = rule.get("id")
                a.remediate = rule.get("remediate")
                a.references = rule.get("references")
                break


def prioritise(inv: Inventory, rules: dict, lifetimes: dict,
               migration_years: dict | None = None) -> None:
    """Tier assets by Mosca X+Y−Z and reachability/lifetime tags."""
    scen = rules.get("scenario", {})
    z = float(scen.get("crqc_horizon_years", 12))
    y_default = scen.get("migration_years_default",
                         {"quantum_broken": 2.0, "quantum_weakened": 1.0})
    default_x = float(lifetimes.get("default_years", 3))
    tag_x = {t["tag"]: float(t["years"]) for t in lifetimes.get("tags", [])}

    for a in inv.assets:
        if a.exposure_class in ("pq_ready", "hybrid"):
            a.tier = "P3" if a.exposure_class == "hybrid" else "OK"
            continue
        tags = a.tag_union()
        x = max([tag_x[t] for t in tags if t in tag_x] or [default_x])
        y = float((migration_years or {}).get(a.asset_id,
                  y_default.get(a.exposure_class, 1.0)))
        gap = x + y - z
        external = "external" in tags
        if a.exposure_class == "quantum_broken" and gap > 0 and external:
            a.tier = "P0"
        elif a.exposure_class == "quantum_broken" and (gap > 0 or external):
            a.tier = "P1"
        elif a.exposure_class == "quantum_broken":
            a.tier = "P2"
        elif a.exposure_class == "quantum_weakened":
            a.tier = "P2" if gap > 0 else "P3"
        else:  # unknown
            a.tier = "P2"
        a.rationale = (a.rationale or "") + f" | Mosca X={x} Y={y} Z={z} gap={gap:+.1f}"


def assess(cbom_path: str, rules_path: str, lifetimes_path: str, out_path: str) -> dict:
    inv = Inventory.load(cbom_path)
    rules = load_rules(rules_path)
    lifetimes = yaml.safe_load(open(lifetimes_path, encoding="utf-8"))
    classify(inv, rules)
    prioritise(inv, rules, lifetimes)
    summary = {"rule_pack": {"version": rules.get("version"), "hash": rules["_hash"]},
               "classes": {}, "tiers": {}}
    for a in inv.assets:
        summary["classes"][a.exposure_class] = summary["classes"].get(a.exposure_class, 0) + 1
        summary["tiers"][a.tier] = summary["tiers"].get(a.tier, 0) + 1
    inv.save(out_path)
    with open(out_path.replace(".json", "") + ".summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    return summary
