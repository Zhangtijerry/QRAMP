# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.vex — Vulnerability Exploitability eXchange for crypto findings.

A scan reports every weak-crypto usage, but many are not actually exploitable in
a given deployment: the code path is unreachable, the algorithm is only used in a
test fixture, the finding is already mitigated by a compensating control, or a
migration is scheduled and accepted for now. VEX lets a team record those
exceptions as versioned, auditable data so the CI gate and the dashboard stop
flagging what has already been triaged — without silently editing the rule pack.

A VEX statement targets a cryptographic asset by its stable `asset_id`
(optionally narrowed to a locator) and assigns a status from the standard VEX
vocabulary. QRAMP reads a VEX document, applies it to an inventory (marking
matched assets suppressed with the justification), and can emit the exceptions in
two standard shapes:

  * OpenVEX      — a standalone JSON document (`@context`, `statements[]`).
  * CycloneDX VEX — a `vulnerabilities[]` array with `analysis.state`, suitable
    for embedding in the CBOM.

Suppressed findings also carry through to SARIF as native `suppressions[]`, which
GitHub code scanning honours, so an accepted risk shows as "dismissed" rather
than re-alerting on every run.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --- the standard VEX vocabulary ------------------------------------------
# status values (OpenVEX / CSAF aligned)
STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
# justifications are REQUIRED by OpenVEX when status == not_affected
JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
# map VEX status -> CycloneDX 1.6 analysis.state
_CDX_STATE = {
    "not_affected": "not_affected",
    "affected": "exploitable",
    "fixed": "resolved",
    "under_investigation": "in_triage",
}
# map OpenVEX justification -> CycloneDX analysis.justification
_CDX_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}


@dataclass
class VexStatement:
    asset_id: str                       # target crypto asset (A-...)
    status: str = "not_affected"
    justification: str = ""             # required for not_affected
    detail: str = ""                    # free-text impact statement
    locator: str = ""                   # optional: narrow to one occurrence location

    def matches(self, asset, occ=None) -> bool:
        if asset.asset_id != self.asset_id:
            return False
        if self.locator and occ is not None:
            return occ.locator == self.locator
        return True


@dataclass
class Finding:
    level: str
    stmt_id: str
    message: str


def parse(doc: dict) -> list[VexStatement]:
    """Parse a QRAMP VEX document (our editable YAML/JSON form) into
    statements. The native form is a list under `statements` with `asset`,
    `status`, `justification`, `detail`, `locator` keys."""
    out = []
    for s in doc.get("statements", []):
        out.append(VexStatement(
            asset_id=s.get("asset") or s.get("asset_id", ""),
            status=s.get("status", "not_affected"),
            justification=s.get("justification", ""),
            detail=s.get("detail", ""),
            locator=s.get("locator", ""),
        ))
    return out


def lint(doc: dict) -> list[Finding]:
    """Static-check a VEX document, mirroring the other linters."""
    findings: list[Finding] = []
    stmts = doc.get("statements", [])
    if not stmts:
        findings.append(Finding("warning", "-", "VEX document has no statements"))
    seen = set()
    for i, s in enumerate(stmts):
        sid = s.get("asset") or s.get("asset_id") or f"<statement #{i}>"
        target = s.get("asset") or s.get("asset_id")
        if not target:
            findings.append(Finding("error", sid, "statement is missing 'asset'"))
        loc = s.get("locator", "")
        dedup = (target, loc)
        if dedup in seen:
            findings.append(Finding("warning", sid,
                f"duplicate statement for asset {target}"
                + (f" at {loc}" if loc else "")))
        seen.add(dedup)
        status = s.get("status", "not_affected")
        if status not in STATUSES:
            findings.append(Finding("error", sid,
                f"unknown status {status!r}; valid: {sorted(STATUSES)}"))
        just = s.get("justification", "")
        if status == "not_affected":
            if not just:
                findings.append(Finding("error", sid,
                    "status 'not_affected' requires a 'justification'"))
            elif just not in JUSTIFICATIONS:
                findings.append(Finding("warning", sid,
                    f"justification {just!r} is not a standard value; "
                    f"valid: {sorted(JUSTIFICATIONS)}"))
        elif just:
            findings.append(Finding("info", sid,
                f"justification is only meaningful for 'not_affected' (status is {status!r})"))
    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.level])
    return findings


def apply(inv, statements: list[VexStatement]) -> dict:
    """Apply VEX statements to an inventory, tagging matched assets with a
    suppression record. Returns a summary. Only 'not_affected' and 'fixed'
    suppress a finding; 'affected'/'under_investigation' are recorded but do not
    suppress."""
    suppressing = {"not_affected", "fixed"}
    by_id = {a.asset_id: a for a in inv.assets}
    applied = matched_assets = 0
    unmatched = []
    for st in statements:
        a = by_id.get(st.asset_id)
        if a is None:
            unmatched.append(st.asset_id)
            continue
        rec = {"status": st.status, "justification": st.justification,
               "detail": st.detail, "locator": st.locator,
               "suppressed": st.status in suppressing}
        # store on the asset (a list; a locator-scoped statement may co-exist)
        if not hasattr(a, "vex") or a.vex is None:
            a.vex = []
        a.vex.append(rec)
        applied += 1
        matched_assets += 1
    return {"statements": len(statements), "applied": applied,
            "unmatched": unmatched,
            "suppressed_assets": sum(1 for a in inv.assets if _is_suppressed(a))}


def _is_suppressed(asset) -> bool:
    recs = getattr(asset, "vex", None)
    return bool(recs) and any(r.get("suppressed") for r in recs)


def suppression_for(asset, occ=None):
    """Return the winning suppression record for an asset/occurrence, or None.
    A locator-scoped statement only suppresses its own occurrence; an unscoped
    one suppresses all occurrences of the asset."""
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


# --- export: OpenVEX -------------------------------------------------------
def to_openvex(inv, statements: list[VexStatement], *, author: str = "qramp") -> dict:
    """Emit an OpenVEX document. Each statement's product is the asset's bom-ref
    (asset_id); the 'vulnerability' is the QRAMP exposure the asset carries."""
    by_id = {a.asset_id: a for a in inv.assets}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out_stmts = []
    for st in statements:
        a = by_id.get(st.asset_id)
        vuln_name = (a.exposure_class if a else "quantum-exposure") or "quantum-exposure"
        stmt = {
            "vulnerability": {"name": f"qramp:{vuln_name}",
                              "description": (a.display if a else st.asset_id)},
            "products": [{"@id": f"qramp:asset:{st.asset_id}"}],
            "status": st.status,
        }
        if st.status == "not_affected" and st.justification:
            stmt["justification"] = st.justification
        if st.detail:
            stmt["impact_statement"] = st.detail
        out_stmts.append(stmt)
    doc_id = "qramp-vex-" + hashlib.sha256(
        "".join(s["products"][0]["@id"] for s in out_stmts).encode()
    ).hexdigest()[:12] if out_stmts else "qramp-vex-empty"
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://qramp/vex/{doc_id}",
        "author": author,
        "timestamp": now,
        "version": 1,
        "statements": out_stmts,
    }


# --- export: CycloneDX VEX -------------------------------------------------
def to_cyclonedx_vex(inv, statements: list[VexStatement]) -> list[dict]:
    """Emit a CycloneDX `vulnerabilities` array expressing the analysis for each
    targeted asset. Meant to be merged into a CycloneDX CBOM."""
    by_id = {a.asset_id: a for a in inv.assets}
    vulns = []
    for st in statements:
        a = by_id.get(st.asset_id)
        vuln_id = f"qramp-{(a.exposure_class if a else 'exposure') or 'exposure'}"
        analysis = {"state": _CDX_STATE.get(st.status, "in_triage")}
        if st.status == "not_affected" and st.justification:
            j = _CDX_JUSTIFICATION.get(st.justification)
            if j:
                analysis["justification"] = j
        if st.detail:
            analysis["detail"] = st.detail
        vulns.append({
            "id": vuln_id,
            "bom-ref": f"vex-{st.asset_id}",
            "description": (a.display if a else st.asset_id),
            "analysis": analysis,
            "affects": [{"ref": st.asset_id}],
        })
    return vulns
