# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.providermap — version-aware resolution and linting of the provider map.

The provider map states which cryptographic capabilities a software component
ships. It is version-aware: a `provides` entry may carry a `version` constraint
(PEP 440 / simple comparator syntax such as ">=3.5" or ">=1.1.0,<3.0"); an entry
with no constraint applies to every version. This module resolves which entries
apply to a concrete component version and statically lints the map for editing
mistakes, mirroring the rule-pack linter's philosophy.

Version handling degrades gracefully: `packaging` is used when available for
correct PEP 440 semantics, otherwise a small built-in comparator parser handles
the common `>=`, `>`, `<=`, `<`, `==`, `!=` forms.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .model import PRIMITIVES, canon_algorithm

try:
    from packaging.version import Version, InvalidVersion
    from packaging.specifiers import SpecifierSet, InvalidSpecifier
    _HAVE_PACKAGING = True
except Exception:                       # pragma: no cover
    _HAVE_PACKAGING = False


_COMPARATORS = ("<=", ">=", "==", "!=", "<", ">")


# --- version constraint handling ------------------------------------------
def _parse_version_tuple(v: str) -> tuple:
    """Very small fallback version parser: split on dots, numeric where possible."""
    parts = re.split(r"[.\-+]", str(v))
    out = []
    for p in parts:
        m = re.match(r"(\d+)", p)
        out.append(int(m.group(1)) if m else 0)
    return tuple(out) or (0,)


def _cmp_tuple(a: tuple, b: tuple) -> int:
    la = list(a) + [0] * (len(b) - len(a))
    lb = list(b) + [0] * (len(a) - len(b))
    return (la > lb) - (la < lb)


def _fallback_satisfies(version: str, spec: str) -> bool:
    """Evaluate a comma-separated comparator constraint without `packaging`."""
    v = _parse_version_tuple(version)
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        op = next((c for c in _COMPARATORS if clause.startswith(c)), None)
        if op is None:
            # bare version means "==" in this simple grammar
            op, rhs = "==", clause
        else:
            rhs = clause[len(op):].strip()
        r = _parse_version_tuple(rhs)
        c = _cmp_tuple(v, r)
        ok = {"<=": c <= 0, ">=": c >= 0, "==": c == 0, "!=": c != 0,
              "<": c < 0, ">": c > 0}[op]
        if not ok:
            return False
    return True


def constraint_is_valid(spec: str) -> bool:
    if not spec:
        return True
    if _HAVE_PACKAGING:
        try:
            SpecifierSet(_normalise_spec(spec))
            return True
        except InvalidSpecifier:
            return False
    # fallback: every clause must start with a known comparator or be a bare version
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        op = next((c for c in _COMPARATORS if clause.startswith(c)), None)
        rhs = clause[len(op):].strip() if op else clause
        if not re.match(r"^\d", rhs):
            return False
    return True


def _normalise_spec(spec: str) -> str:
    """packaging wants '==3.5' style; a bare '3.5' clause is treated as '==3.5'."""
    out = []
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        if not any(clause.startswith(c) for c in _COMPARATORS):
            clause = "==" + clause
        out.append(clause)
    return ",".join(out)


def satisfies(version: str, spec: str | None) -> bool:
    """Does `version` satisfy the constraint `spec`? An empty/None spec always
    matches. An unknown/'?' version conservatively matches unconstrained entries
    only (a version we can't parse should not be assumed to be new enough for a
    version-gated capability)."""
    if not spec:
        return True
    if version in (None, "", "?", "unknown"):
        return False                    # can't confirm a version gate; fail closed
    if _HAVE_PACKAGING:
        try:
            return Version(str(version)) in SpecifierSet(_normalise_spec(spec))
        except (InvalidVersion, InvalidSpecifier):
            return _fallback_satisfies(version, spec)
    return _fallback_satisfies(version, spec)


# --- resolution -----------------------------------------------------------
@dataclass
class ResolvedProvide:
    primitive: str
    algorithm: str
    params: str = ""
    key_length: int | None = None
    confidence: float = 0.7
    version_gate: str = ""              # the constraint that admitted this entry (if any)


def resolve(entry: dict, version: str) -> list[ResolvedProvide]:
    """Return the provides entries of a component that apply at `version`."""
    out = []
    for p in entry.get("provides", []):
        gate = p.get("version", "")
        if gate and not satisfies(version, gate):
            continue
        out.append(ResolvedProvide(
            primitive=p["primitive"], algorithm=p["algorithm"],
            params=p.get("params", ""), key_length=p.get("key_length"),
            confidence=float(p.get("confidence", 0.7)), version_gate=gate))
    return out


# --- lint -----------------------------------------------------------------
@dataclass
class Finding:
    level: str
    component: str
    message: str


def lint(doc: dict) -> list[Finding]:
    """Static-check a provider map for editing mistakes."""
    findings: list[Finding] = []
    comps = doc.get("components", [])
    if not comps:
        findings.append(Finding("error", "-", "provider map has no components"))
        return findings

    seen: dict[str, int] = {}
    for i, entry in enumerate(comps):
        name = entry.get("component")
        cid = name or f"<component #{i}>"
        if not name:
            findings.append(Finding("error", cid, "component entry is missing 'component'"))
        else:
            key = name.lower()
            if key in seen:
                findings.append(Finding("error", cid,
                    f"duplicate component (first at position {seen[key]}); "
                    f"merge the provides lists"))
            seen.setdefault(key, i)
        provides = entry.get("provides", [])
        if not provides:
            findings.append(Finding("warning", cid, "component has no 'provides' entries"))
        # track (primitive, algorithm, params) to detect duplicate/conflicting
        # capability rows within one component
        seen_caps: dict[tuple, str] = {}
        for p in provides:
            prim = p.get("primitive")
            alg = p.get("algorithm")
            if prim is None or alg is None:
                findings.append(Finding("error", cid,
                    "a provides entry is missing 'primitive' or 'algorithm'"))
                continue
            if prim not in PRIMITIVES:
                findings.append(Finding("warning", cid,
                    f"primitive {prim!r} is not in the known set {PRIMITIVES}"))
            if canon_algorithm(alg) != alg:
                findings.append(Finding("info", cid,
                    f"algorithm {alg!r} is not canonical; canonical form is "
                    f"{canon_algorithm(alg)!r}"))
            conf = p.get("confidence")
            if conf is not None:
                try:
                    cf = float(conf)
                    if not 0.0 <= cf <= 1.0:
                        findings.append(Finding("error", cid,
                            f"confidence {conf} for {alg} is outside [0,1]"))
                except (TypeError, ValueError):
                    findings.append(Finding("error", cid,
                        f"confidence {conf!r} for {alg} is not a number"))
            gate = p.get("version", "")
            if gate and not constraint_is_valid(gate):
                findings.append(Finding("error", cid,
                    f"invalid version constraint {gate!r} for {alg}"))
            kl = p.get("key_length")
            if kl is not None and (not isinstance(kl, int) or kl <= 0):
                findings.append(Finding("error", cid,
                    f"key_length {kl!r} for {alg} must be a positive integer"))
            # duplicate capability row (same prim/alg/params) with an
            # overlapping/unconstrained gate is ambiguous
            capkey = (prim, canon_algorithm(alg), p.get("params", ""))
            prev_gate = seen_caps.get(capkey)
            if prev_gate is not None:
                if not gate or not prev_gate:
                    findings.append(Finding("warning", cid,
                        f"capability {alg} ({prim}) is listed more than once with "
                        f"an unconstrained version — the entries collide"))
            seen_caps[capkey] = gate

    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.level])
    return findings
