# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.rulelint — static analysis and regression testing for rule packs.

The rule pack is editable, versioned YAML policy consumed by assess.classify()
with FIRST-MATCH-WINS semantics: rule order decides the outcome. That makes two
classes of editing mistake easy and silent — a rule that can never fire because
an earlier, broader rule always matches first (unreachable), and two rules that
can both match the same asset but assign different classes (ambiguous overlap,
silently resolved by order). This module finds both by reasoning about the match
predicate directly, plus checks syntax and supports snapshot regression so a
policy edit shows exactly which known assets changed classification.

The linter mirrors assess._match exactly; if the matcher gains a condition, the
Condition model here must gain it too (guarded by a test).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .model import PRIMITIVES

VALID_CLASSES = {"pq_ready", "hybrid", "quantum_broken", "quantum_weakened", "unknown"}
VALID_MATCH_KEYS = {"primitive", "algorithm", "params",
                    "max_key_length", "min_key_length", "has_tag"}
VALID_ACTIONS = {"decommission", "reissue", None}
# remediate keys the plan/verify layers understand
VALID_REMEDIATE_KEYS = {"action", "require_min_key_length", "require_algorithm",
                        "require_signature_hash", "require_forward_secrecy",
                        "min_key_length", "min_curve_bits", "prefer"}

VALID_REFERENCE_KEYS = {"standard", "section", "note", "url"}

# recognised standards-body prefixes for a provenance citation. A citation that
# does not start with one of these is flagged (info) as possibly non-standard.
import re as _re
_STANDARD_RE = _re.compile(
    r"^(FIPS|NIST SP|NISTIR|NIST IR|NIST policy|RFC|ISO|ISO/IEC|CVE|"
    r"draft-|BSI|ETSI|ANSSI|PKCS)\b", _re.IGNORECASE)


def _looks_like_standard(s: str) -> bool:
    return bool(_STANDARD_RE.match(str(s).strip()))


def _as_set(v):
    if v is None:
        return None                       # ANY
    return set(v) if isinstance(v, list) else {v}


@dataclass
class Condition:
    """A rule's match clause as a predicate over the asset space. `None` on a
    dimension means "unconstrained" (matches anything on that dimension)."""
    primitive: set | None = None
    algorithm: set | None = None
    params: set | None = None
    kmin: int | None = None               # inclusive lower bound on key_length
    kmax: int | None = None               # inclusive upper bound on key_length
    has_tag: set | None = None            # intersection semantics

    @classmethod
    def from_match(cls, m: dict) -> "Condition":
        return cls(
            primitive=_as_set(m.get("primitive")),
            algorithm=_as_set(m.get("algorithm")),
            params=_as_set(m.get("params")),
            kmin=m.get("min_key_length"),
            kmax=m.get("max_key_length"),
            has_tag=_as_set(m.get("has_tag")),
        )

    def constrains_key_length(self) -> bool:
        return self.kmin is not None or self.kmax is not None


def _set_superseteq(a: set | None, b: set | None) -> bool:
    """Does condition-side a admit at least everything b admits, on a set
    dimension? a=None is ANY (admits all)."""
    if a is None:
        return True
    if b is None:
        return False              # a restricts, b is open -> a is narrower
    return a >= b


def _range_superseteq(amin, amax, bmin, bmax) -> bool:
    """Does the key-length range of a contain that of b? None bounds are open."""
    # a's lower bound must be <= b's effective lower bound
    if amin is not None and (bmin is None or amin > bmin):
        return False
    if amax is not None and (bmax is None or amax < bmax):
        return False
    return True


def _tag_superseteq(a: set | None, b: set | None) -> bool:
    """has_tag uses intersection semantics (match if asset shares any listed
    tag). a admits >= b iff: a is unconstrained, or b is constrained and every
    tag that satisfies b also satisfies a — guaranteed only when a >= b."""
    if a is None:
        return True
    if b is None:
        return False              # a needs a tag, b matches tagless assets too
    return a >= b


def subsumes(a: Condition, b: Condition) -> bool:
    """True if every asset matching b also matches a (a's match-set ⊇ b's).
    Used to detect that an earlier rule `a` makes a later rule `b` unreachable."""
    return (
        _set_superseteq(a.primitive, b.primitive)
        and _set_superseteq(a.algorithm, b.algorithm)
        and _set_superseteq(a.params, b.params)
        and _range_superseteq(a.kmin, a.kmax, b.kmin, b.kmax)
        and _tag_superseteq(a.has_tag, b.has_tag)
    )


def _sets_can_intersect(a: set | None, b: set | None) -> bool:
    if a is None or b is None:
        return True
    return bool(a & b)


def _ranges_can_intersect(amin, amax, bmin, bmax) -> bool:
    lo = max(x for x in (amin, bmin) if x is not None) if (amin or bmin) else None
    hi = min(x for x in (amax, bmax) if x is not None) if (amax or bmax) else None
    if lo is not None and hi is not None:
        return lo <= hi
    return True


def _tags_can_intersect(a: set | None, b: set | None) -> bool:
    # both use intersection semantics; an asset could carry tags satisfying both
    if a is None or b is None:
        return True
    return True         # an asset may carry tags from both sets simultaneously


def can_overlap(a: Condition, b: Condition) -> bool:
    """True if some asset could match both a and b (their match-sets intersect).
    Two overlapping rules with different classes are an ordering-dependent
    ambiguity worth flagging."""
    return (
        _sets_can_intersect(a.primitive, b.primitive)
        and _sets_can_intersect(a.algorithm, b.algorithm)
        and _sets_can_intersect(a.params, b.params)
        and _ranges_can_intersect(a.kmin, a.kmax, b.kmin, b.kmax)
        and _tags_can_intersect(a.has_tag, b.has_tag)
    )


def _shares_constrained_dimension(a: Condition, b: Condition) -> bool:
    """Do a and b both constrain the *same* dimension with intersecting values?
    Overlap is only a meaningful ambiguity when the rules actually compete on a
    shared axis (e.g. both name algorithm rsa). When they constrain disjoint
    dimensions (one names an algorithm, the other only a param), the abstract
    match-sets may intersect but the rules are not realistically ambiguous, so
    we suppress the noise."""
    if a.algorithm is not None and b.algorithm is not None:
        return bool(a.algorithm & b.algorithm)
    if a.params is not None and b.params is not None:
        return bool(a.params & b.params)
    if a.primitive is not None and b.primitive is not None:
        # a shared primitive is only a real clash if at least one of the other
        # discriminating dimensions is also shared or open on both sides
        if not (a.primitive & b.primitive):
            return False
        alg_open = a.algorithm is None and b.algorithm is None
        param_open = a.params is None and b.params is None
        tag_open = a.has_tag is None or b.has_tag is None
        return alg_open or param_open or tag_open
    return False


@dataclass
class Finding:
    level: str            # "error" | "warning" | "info"
    rule_id: str
    message: str


def lint(rules_doc: dict) -> list[Finding]:
    """Static-analyse a parsed rule pack. Returns findings ordered
    errors-first."""
    findings: list[Finding] = []
    rules = rules_doc.get("rules", [])
    if not rules:
        findings.append(Finding("error", "-", "rule pack has no rules"))
        return findings

    # --- per-rule syntax ---
    seen_ids: dict[str, int] = {}
    conds: list[tuple[str, Condition, str]] = []   # (id, condition, class)
    for i, r in enumerate(rules):
        rid = r.get("id", f"<rule #{i}>")
        if "id" not in r:
            findings.append(Finding("error", rid, "rule is missing an 'id'"))
        if rid in seen_ids:
            findings.append(Finding("error", rid,
                                    f"duplicate id (first seen at position {seen_ids[rid]})"))
        seen_ids.setdefault(rid, i)
        cls = r.get("class")
        if cls is None:
            findings.append(Finding("error", rid, "rule is missing a 'class'"))
        elif cls not in VALID_CLASSES:
            findings.append(Finding("error", rid,
                                    f"unknown class {cls!r}; valid: {sorted(VALID_CLASSES)}"))
        m = r.get("match", {})
        if not isinstance(m, dict) or not m:
            findings.append(Finding("error", rid, "rule has an empty or invalid 'match'"))
        else:
            for k in m:
                if k not in VALID_MATCH_KEYS:
                    findings.append(Finding("error", rid,
                                            f"unknown match key {k!r}; valid: {sorted(VALID_MATCH_KEYS)}"))
            prim = _as_set(m.get("primitive"))
            if prim:
                for p in prim:
                    if p not in PRIMITIVES:
                        findings.append(Finding("warning", rid,
                                                f"primitive {p!r} is not in the known set {PRIMITIVES}"))
            kmin, kmax = m.get("min_key_length"), m.get("max_key_length")
            if kmin is not None and kmax is not None and kmin > kmax:
                findings.append(Finding("error", rid,
                                        f"min_key_length {kmin} > max_key_length {kmax}: matches nothing"))
        rem = r.get("remediate")
        if rem is not None:
            if not isinstance(rem, dict):
                findings.append(Finding("error", rid, "'remediate' must be a mapping"))
            else:
                if rem.get("action") not in VALID_ACTIONS:
                    findings.append(Finding("warning", rid,
                                            f"remediate.action {rem.get('action')!r} not in {sorted(a for a in VALID_ACTIONS if a)}"))
                for k in rem:
                    if k not in VALID_REMEDIATE_KEYS:
                        findings.append(Finding("info", rid,
                                                f"remediate key {k!r} is not consumed by plan/verify"))

        # --- provenance: every rule should cite a governing standard ---
        refs = r.get("references")
        if refs is None:
            findings.append(Finding("warning", rid,
                "rule has no 'references'; add the governing standard "
                "(FIPS/NIST SP/RFC) so the classification is auditable"))
        elif not isinstance(refs, list):
            findings.append(Finding("error", rid, "'references' must be a list"))
        else:
            for ref in refs:
                if not isinstance(ref, dict):
                    findings.append(Finding("error", rid,
                        "each reference must be a mapping with a 'standard'"))
                    continue
                std = ref.get("standard")
                if not std:
                    findings.append(Finding("error", rid,
                        "a reference is missing 'standard'"))
                    continue
                if not _looks_like_standard(std):
                    findings.append(Finding("info", rid,
                        f"reference {std!r} does not look like a recognised "
                        f"standard id (FIPS/NIST SP/NISTIR/RFC/ISO/CVE/...)"))
                for k in ref:
                    if k not in VALID_REFERENCE_KEYS:
                        findings.append(Finding("info", rid,
                            f"reference key {k!r} is not a recognised field "
                            f"(standard/section/note/url)"))
                url = ref.get("url")
                if url is not None and not str(url).startswith(("http://", "https://")):
                    findings.append(Finding("warning", rid,
                        f"reference url {url!r} is not an http(s) URL"))
        # only build a Condition if match is usable
        if isinstance(m, dict) and m and all(k in VALID_MATCH_KEYS for k in m):
            conds.append((rid, Condition.from_match(m), cls))

    # --- unreachable (shadowed) rules: an earlier rule subsumes this one ---
    for j in range(len(conds)):
        rid_j, cond_j, _ = conds[j]
        for i in range(j):
            rid_i, cond_i, _ = conds[i]
            if subsumes(cond_i, cond_j):
                findings.append(Finding("warning", rid_j,
                    f"unreachable: rule {rid_i!r} above it matches a superset, "
                    f"so {rid_j!r} can never fire"))
                break

    # --- ambiguous overlap: two rules can match the same asset with different
    #     classes. Only report the first (winning) vs later pair, and skip pairs
    #     already explained by subsumption (those are 'unreachable', not
    #     'ambiguous'). ---
    for i in range(len(conds)):
        rid_i, cond_i, cls_i = conds[i]
        for j in range(i + 1, len(conds)):
            rid_j, cond_j, cls_j = conds[j]
            if cls_i == cls_j:
                continue
            if subsumes(cond_i, cond_j):
                continue      # j is unreachable under i; already reported
            if can_overlap(cond_i, cond_j) and _shares_constrained_dimension(cond_i, cond_j):
                findings.append(Finding("info", rid_j,
                    f"overlaps {rid_i!r} (class {cls_i}) with different class "
                    f"{cls_j}; order decides — {rid_i!r} wins for shared assets"))

    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.level])
    return findings


# --- snapshot regression --------------------------------------------------
def classify_snapshot(rules_doc: dict, assets: list[dict]) -> dict:
    """Classify a list of plain-dict assets against the rule pack and return a
    stable {asset_label: {class, rule}} map. Used to freeze a known-good
    baseline and diff future edits against it."""
    from .model import Inventory, Occurrence, canon_algorithm
    from . import assess

    inv = Inventory()
    labels = {}
    for spec in assets:
        occ = Occurrence(collector="snapshot", locator=spec.get("label", "?"),
                         evidence="snapshot fixture",
                         tags=list(spec.get("tags", [])))
        a = inv.observe(spec["primitive"], spec["algorithm"], occ,
                        params=spec.get("params", ""),
                        key_length=spec.get("key_length"),
                        mode=spec.get("mode", ""))
        labels[a.key] = spec.get("label") or a.display

    # classify, capturing which rule id fired
    out = {}
    rules = rules_doc.get("rules", [])
    for a in inv.assets:
        fired, cls = None, "unknown"
        for r in rules:
            if assess._match(r, a):
                fired, cls = r.get("id"), r.get("class")
                break
        out[labels[a.key]] = {"class": cls, "rule": fired}
    return out


def diff_snapshot(baseline: dict, current: dict) -> dict:
    """Diff two snapshots. Reports assets whose class or firing rule changed,
    plus assets only present on one side."""
    changed = []
    for label, cur in current.items():
        base = baseline.get(label)
        if base is None:
            continue
        if base.get("class") != cur.get("class") or base.get("rule") != cur.get("rule"):
            changed.append({"asset": label, "was": base, "now": cur})
    only_baseline = sorted(set(baseline) - set(current))
    only_current = sorted(set(current) - set(baseline))
    return {"changed": changed, "only_in_baseline": only_baseline,
            "only_in_current": only_current,
            "regressions": len(changed)}
