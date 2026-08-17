# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.readiness — migration readiness scoring and ROI-ranked upgrade advice.

The version-aware provider map knows which library versions ship post-quantum
capabilities (e.g. OpenSSL gains ML-KEM/ML-DSA at 3.5, BouncyCastle at 1.78).
The dependency graph knows which libraries are actually deployed and at what
version. Combining them answers the planning question:

    "Upgrading OpenSSL 3.0.13 -> 3.5 unlocks ML-KEM and ML-DSA, unblocking the
     N key-agreement and M signature assets that are currently stuck at P0/P1
     because nothing in the stack can provide a quantum-safe replacement."

The key concept is *migration-blocked*: a quantum-broken asset can only migrate
to PQC if some deployed library provides the quantum-safe primitive it needs
(key-agreement -> ML-KEM, signature -> ML-DSA). If none does, the asset is
blocked and the fix is a library upgrade, not a code change alone. This module
finds those blocks and ranks the upgrades that clear the most weighted risk per
unit of upgrade distance (a simple ROI proxy).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .providermap import resolve, satisfies

# the quantum-safe primitive that replaces each broken primitive
PQ_REPLACEMENT = {
    "key-agreement": "ml-kem",       # KEM replaces classical key exchange
    "pk-encryption": "ml-kem",       # KEM-based hybrid replaces RSA encryption
    "signature": "ml-dsa",           # ML-DSA replaces classical signatures
}
# tier weights for the ROI numerator (risk cleared)
TIER_WEIGHT = {"P0": 8.0, "P1": 4.0, "P2": 2.0, "P3": 1.0, "OK": 0.0, None: 0.5}


def _pq_algorithms() -> set:
    return set(PQ_REPLACEMENT.values())


def blocked_assets(inv) -> list:
    """Return the quantum-broken/weakened assets whose quantum-safe replacement
    primitive is provided by NO currently deployed library — i.e. migration is
    blocked on a capability the stack does not yet have."""
    pq = _pq_algorithms()
    # which PQ algorithms does the *current* deployment already provide?
    provided_pq = set()
    for c in inv.components:
        for a in inv.assets_provided_by(c):
            if a.algorithm in pq:
                provided_pq.add(a.algorithm)

    out = []
    for a in inv.assets:
        if a.exposure_class not in ("quantum_broken", "quantum_weakened"):
            continue
        need = PQ_REPLACEMENT.get(a.primitive)
        if need is None:
            continue                      # e.g. a hash — not a KEM/sig migration
        if need not in provided_pq:
            out.append(a)
    return out


@dataclass
class UpgradeOption:
    component: str
    from_version: str
    to_version: str
    unlocks: list = field(default_factory=list)     # PQ algorithms newly available
    unblocks: list = field(default_factory=list)    # assets it would unblock (CryptoAsset)
    tiers: dict = field(default_factory=dict)        # tier -> count among unblocked
    score: float = 0.0

    def as_dict(self) -> dict:
        return {
            "component": self.component,
            "upgrade": f"{self.from_version} -> {self.to_version}",
            "unlocks": sorted(self.unlocks),
            "unblocks": len(self.unblocks),
            "by_tier": self.tiers,
            "roi_score": round(self.score, 2),
            "examples": [a.display for a in self.unblocks[:5]],
        }


def _candidate_versions(entry: dict) -> list[str]:
    """Derive the versions worth considering from a component's version gates.
    Each `>=X` gate contributes X as a candidate 'upgrade to' version (the first
    version at which the gated capability becomes available)."""
    versions = []
    for p in entry.get("provides", []):
        gate = p.get("version", "")
        if gate.startswith(">="):
            v = gate[2:].split(",")[0].strip()
            if v and v not in versions:
                versions.append(v)
    return versions


def upgrade_options(inv, provider_map: dict) -> list[UpgradeOption]:
    """For each deployed, mapped component, compute the upgrade(s) that would
    unlock a PQ capability and unblock currently-blocked assets. Ranked by ROI."""
    entries = {e["component"].lower(): e for e in provider_map.get("components", [])}
    blocked = blocked_assets(inv)
    pq = _pq_algorithms()

    # index blocked assets by the PQ algorithm that would unblock them
    blocked_by_need: dict[str, list] = {}
    for a in blocked:
        need = PQ_REPLACEMENT.get(a.primitive)
        blocked_by_need.setdefault(need, []).append(a)

    options: list[UpgradeOption] = []
    for comp in inv.components:
        entry = entries.get(comp.name.lower())
        if entry is None:
            continue
        cur = comp.version
        # what PQ algs does this component ALREADY provide at its current version?
        cur_pq = {p.algorithm for p in resolve(entry, cur) if p.algorithm in pq}
        for to_v in _candidate_versions(entry):
            # only a real upgrade: current version must NOT already satisfy it
            if satisfies(cur, f">={to_v}"):
                continue
            # PQ algs available AFTER the upgrade
            after_pq = {p.algorithm for p in resolve(entry, to_v) if p.algorithm in pq}
            newly = after_pq - cur_pq
            if not newly:
                continue
            # which blocked assets does this newly-unlocked capability serve?
            unblocked = []
            for alg in newly:
                unblocked.extend(blocked_by_need.get(alg, []))
            # de-dup by asset key
            seen = set(); uniq = []
            for a in unblocked:
                if a.key not in seen:
                    seen.add(a.key); uniq.append(a)
            if not uniq:
                continue
            tiers: dict = {}
            weight = 0.0
            for a in uniq:
                tiers[a.tier] = tiers.get(a.tier, 0) + 1
                weight += TIER_WEIGHT.get(a.tier, 0.5)
            # ROI proxy: risk cleared per unit of upgrade distance. Distance is a
            # coarse major/minor version jump so a small bump that clears P0s
            # ranks above a big jump that clears P3s.
            distance = _version_distance(cur, to_v)
            score = weight / distance
            options.append(UpgradeOption(
                component=comp.name, from_version=cur, to_version=to_v,
                unlocks=list(newly), unblocks=uniq, tiers=tiers, score=score))

    options.sort(key=lambda o: o.score, reverse=True)
    return options


def _version_distance(cur: str, to: str) -> float:
    """A coarse upgrade-effort proxy: 1 + the magnitude of the major/minor jump.
    Unknown/unparseable current version -> treat as a full major upgrade."""
    def parse(v):
        import re
        parts = re.split(r"[.\-+]", str(v))
        nums = []
        for p in parts[:2]:
            m = re.match(r"(\d+)", p)
            nums.append(int(m.group(1)) if m else 0)
        while len(nums) < 2:
            nums.append(0)
        return nums
    if cur in (None, "", "?", "unknown"):
        return 3.0
    c, t = parse(cur), parse(to)
    major = abs(t[0] - c[0])
    minor = abs(t[1] - c[1]) if major == 0 else t[1]
    return 1.0 + major * 2.0 + minor * 0.5


def readiness_report(inv, provider_map: dict) -> dict:
    """Full readiness summary: of the assets that need a PQC key-agreement or
    signature migration, how many already have a deployable replacement
    capability, and the ROI-ranked upgrades that would clear the rest."""
    # only assets whose migration is a KEM/signature swap are in scope here;
    # hashes / symmetric ciphers are Grover-affected, not a PQC-capability block.
    in_scope = [a for a in inv.assets
                if a.exposure_class in ("quantum_broken", "quantum_weakened")
                and PQ_REPLACEMENT.get(a.primitive) is not None]
    blocked = blocked_assets(inv)
    options = upgrade_options(inv, provider_map)

    n_scope = len(in_scope)
    n_blocked = len(blocked)
    ready = n_scope - n_blocked
    pct = round(100.0 * ready / n_scope, 1) if n_scope else 100.0

    addressable = set()
    for o in options:
        for a in o.unblocks:
            addressable.add(a.key)
    return {
        "pqc_migration_assets": n_scope,
        "migration_blocked": n_blocked,
        "already_migratable": ready,
        "readiness_pct": pct,
        "blocked_addressable_by_upgrade": len(addressable),
        "blocked_unaddressable": n_blocked - len(addressable),
        "recommended_upgrades": [o.as_dict() for o in options],
    }
