# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.sarif — export findings as SARIF 2.1.0 for GitHub code scanning / CI.

Each occurrence of a non-OK cryptographic asset becomes a SARIF *result*, mapped
to the source location the collector recorded (`path:line`), so a weak-crypto
usage lights up on the exact line in a pull request. The rule pack's rules become
SARIF *rules* (rich help text, default severity), and each result carries a
stable partial fingerprint so GitHub can track a finding across commits even if
line numbers shift.

Locators come in three shapes:
  * `path:line`  — source and config collectors -> physicalLocation with region
  * `path`       — certificate files            -> physicalLocation, no region
  * `host:port`  — active TLS probes            -> no artifact; kept as a note in
                   the message (not a file, so no physicalLocation)
Only the first two produce a code-scanning annotation; the third still emits a
result so nothing is silently dropped.
"""
from __future__ import annotations

import hashlib
import os
import re
from urllib.parse import quote

SARIF_VERSION = "2.1.0"
SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
          "Schemas/sarif-schema-2.1.0.json")
TOOL_URI = "https://github.com/qramp/qramp"

# exposure class -> SARIF result level + a human severity label
_LEVEL = {
    "quantum_broken": ("error", "high"),
    "quantum_weakened": ("warning", "medium"),
    "hybrid": ("note", "low"),
    "pq_ready": ("note", "low"),
    "unknown": ("note", "low"),
    None: ("note", "low"),
}
# a security-severity score (GitHub uses this to bucket alerts) by tier
_SECURITY_SEVERITY = {"P0": "9.0", "P1": "7.5", "P2": "5.0", "P3": "3.0",
                      "OK": "0.0", None: "1.0"}

# a host:port locator looks like this
_HOSTPORT = re.compile(r"^[^/\\]+:\d+$")


def _alias_for(locator: str, alias_by_cv: dict):
    """A manifest occurrence locator is `{path}#{component}@{version}`; use it to
    find the alias resolution recorded for that (component, version)."""
    if "#" not in locator:
        return None
    tail = locator.rsplit("#", 1)[1]
    if "@" not in tail:
        return None
    comp, _, ver = tail.rpartition("@")
    return alias_by_cv.get((comp, ver))


def _split_locator(loc: str):
    """Return (uri, line) from a locator. line is None when absent. A host:port
    locator returns (None, None) — it is not a file."""
    if not loc:
        return None, None
    if _HOSTPORT.match(loc):
        return None, None
    # path may itself contain colons on Windows; split on the LAST :<digits>
    m = re.match(r"^(.*):(\d+)$", loc)
    if m:
        return m.group(1), int(m.group(2))
    return loc, None


def _rel_uri(path: str) -> str:
    """Normalise a filesystem path to a repo-relative forward-slash URI."""
    p = path.replace("\\", "/")
    # strip a leading ./ and any absolute prefix the runner won't recognise
    p = re.sub(r"^\./", "", p)
    return quote(p, safe="/._-")


def _fingerprint(asset, occ) -> str:
    """Stable partial fingerprint: identifies the finding by (asset identity,
    file, evidence) but deliberately NOT by line, so a finding survives edits
    that only shift line numbers."""
    uri, _ = _split_locator(occ.locator)
    basis = "|".join([
        asset.primitive, asset.algorithm, asset.params or "",
        str(asset.key_length or ""), asset.mode or "",
        uri or occ.locator, occ.collector,
    ])
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def _rules_from_pack(rules_doc: dict) -> tuple[list, dict]:
    """Build SARIF reportingDescriptor objects from the rule pack. Returns the
    rule list and an index {rule_id: array position} for result.ruleIndex."""
    rules, index = [], {}
    for r in rules_doc.get("rules", []):
        rid = r.get("id")
        if not rid or rid in index:
            continue
        cls = r.get("class")
        level, _sev = _LEVEL.get(cls, ("note", "low"))
        why = r.get("why", "")
        rem = r.get("remediate") or {}
        refs = r.get("references") or []
        help_lines = [why]
        if rem:
            action = rem.get("action")
            if action:
                help_lines.append(f"Remediation action: {action}.")
            targets = {k: v for k, v in rem.items() if k != "action"}
            if targets:
                help_lines.append("Target: " + ", ".join(
                    f"{k}={v}" for k, v in targets.items()) + ".")
        if refs:
            cites = "; ".join(_format_ref(x) for x in refs)
            help_lines.append(f"References: {cites}.")
        index[rid] = len(rules)
        rules.append({
            "id": rid,
            "name": _camel(rid),
            "shortDescription": {"text": why[:120] or rid},
            "fullDescription": {"text": why or rid},
            "helpUri": _ref_uri(refs) or TOOL_URI,
            "help": {"text": "\n".join(l for l in help_lines if l)},
            "defaultConfiguration": {"level": level},
            "properties": {
                "exposureClass": cls,
                "references": [dict(x) for x in refs if isinstance(x, dict)],
                "tags": ["cryptography", "post-quantum",
                         f"exposure/{cls}" if cls else "exposure/unknown"]
                + [f"standard/{x.get('standard')}" for x in refs
                   if isinstance(x, dict) and x.get("standard")],
            },
        })
    return rules, index


def _format_ref(ref) -> str:
    if not isinstance(ref, dict):
        return str(ref)
    std = ref.get("standard", "")
    sec = ref.get("section")
    note = ref.get("note")
    out = std
    if sec:
        out += f" {sec}"
    if note:
        out += f" ({note})"
    return out.strip()


def _ref_uri(refs) -> str | None:
    for x in refs:
        if isinstance(x, dict) and x.get("url"):
            return x["url"]
    return None


def _camel(rule_id: str) -> str:
    return "".join(p.capitalize() for p in re.split(r"[-_]", rule_id)) or rule_id


# a synthetic rule for assets that matched no rule-pack rule
_UNCLASSIFIED = "qramp-unclassified"


def _vex_suppression(asset, occ):
    """Return the winning VEX suppression record for an asset/occurrence, or
    None. Reads the `vex` records that vex.apply() attached to the asset."""
    recs = getattr(asset, "vex", None)
    if not recs:
        return None
    for r in recs:
        if not r.get("suppressed"):
            continue
        loc = r.get("locator")
        if loc and occ is not None and occ.locator != loc:
            continue
        return r
    return None


def to_sarif(inv, rules_doc: dict | None = None, *,
             min_level: str = "note", include_ok: bool = False) -> dict:
    """Serialise an assessed Inventory to a SARIF 2.1.0 document.

    min_level filters results below the given severity ("error" > "warning" >
    "note"); include_ok additionally emits pq_ready/OK assets as note-level
    (useful for a full inventory view, off by default so CI sees only problems).
    """
    rules, index = _rules_from_pack(rules_doc or {})
    # ensure a fallback rule exists
    if _UNCLASSIFIED not in index:
        index[_UNCLASSIFIED] = len(rules)
        rules.append({
            "id": _UNCLASSIFIED,
            "name": "QrampUnclassified",
            "shortDescription": {"text": "Cryptographic asset with no matching policy rule"},
            "defaultConfiguration": {"level": "note"},
            "properties": {"tags": ["cryptography"]},
        })

    rank = {"error": 3, "warning": 2, "note": 1}
    floor = rank.get(min_level, 1)

    # index alias resolutions (from the manifest collector) by (component,
    # version) so a manifest finding can carry how the component was discovered:
    # which package, which ecosystem, whether it is a wrapper or unmapped.
    alias_by_cv: dict = {}
    for c in inv.meta.get("collectors", []):
        if c.get("name") != "manifests":
            continue
        for r in c.get("alias_resolutions", []):
            alias_by_cv.setdefault((r.get("component"), str(r.get("version"))), r)

    results = []
    for a in inv.assets:
        level, _sev = _LEVEL.get(a.exposure_class, ("note", "low"))
        is_ok = a.exposure_class in ("pq_ready", "hybrid") or a.tier in ("OK", "P3")
        if is_ok and not include_ok:
            continue
        if rank[level] < floor:
            continue
        rid = a.rule_id or _UNCLASSIFIED
        if rid not in index:                       # rule pack changed since assess
            rid = _UNCLASSIFIED
        ridx = index[rid]
        sev = _SECURITY_SEVERITY.get(a.tier, "1.0")
        remediation = ""
        if a.remediate:
            act = a.remediate.get("action")
            remediation = (f" Remediation: {act}." if act else "")
        for occ in a.occurrences:
            uri, line = _split_locator(occ.locator)
            msg = (f"{a.display}: {a.rationale or a.exposure_class or 'review'}. "
                   f"Evidence: {occ.evidence}.{remediation}")
            result = {
                "ruleId": rid,
                "ruleIndex": ridx,
                "level": level,
                "message": {"text": msg},
                "partialFingerprints": {"qrampAssetLocation": _fingerprint(a, occ)},
                "properties": {
                    "exposureClass": a.exposure_class,
                    "tier": a.tier,
                    "security-severity": sev,
                    "collector": occ.collector,
                },
            }
            # for a manifest-discovered finding, record how the component was
            # resolved from the package name (traceability for SBOM discovery)
            if occ.collector == "manifests":
                res = _alias_for(occ.locator, alias_by_cv)
                if res:
                    result["properties"]["aliasResolution"] = {
                        "package": res.get("package"),
                        "ecosystem": res.get("ecosystem"),
                        "component": res.get("component"),
                        "wrapper": bool(res.get("wrapper")),
                        "mapped": bool(res.get("mapped", True)),
                    }
                    tags = ["discovery/manifest"]
                    if res.get("wrapper"):
                        tags.append("discovery/wrapper")
                    if not res.get("mapped", True):
                        tags.append("discovery/unmapped")
                    result["properties"]["tags"] = tags
            if uri is not None:
                phys = {"artifactLocation": {"uri": _rel_uri(uri)}}
                if line is not None:
                    phys["region"] = {"startLine": line}
                result["locations"] = [{"physicalLocation": phys}]
            else:
                # not a file (e.g. host:port) — record as a logical location so
                # the finding is not dropped
                result["locations"] = [{
                    "logicalLocations": [{"fullyQualifiedName": occ.locator,
                                          "kind": "resource"}]}]
            # VEX suppression: an accepted exception marks the result dismissed
            # (GitHub honours suppressions[]), so the CI gate stops re-alerting.
            supp = _vex_suppression(a, occ)
            if supp is not None:
                just = supp.get("justification") or supp.get("status") or "accepted"
                detail = supp.get("detail", "").strip()
                s = {"kind": "external",
                     "justification": f"VEX: {just}" + (f" — {detail}" if detail else "")}
                result["suppressions"] = [s]
            results.append(result)

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "QRAMP",
                "informationUri": TOOL_URI,
                "version": "0.1.0",
                "rules": rules,
            }},
            "results": results,
            "columnKind": "unicodeCodePoints",
        }],
    }
