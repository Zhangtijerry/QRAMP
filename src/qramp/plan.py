# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.plan — Layer 4.

Compiles assessed assets into typed tasks, builds a DAG, and schedules it
under change-window/capacity constraints minimising weighted exposure-days.
Uses OR-Tools CP-SAT when available and a deterministic list-scheduling
heuristic otherwise. Every task carries prerequisites, a rollback action and
a machine-checkable acceptance predicate.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict

import yaml

from .model import Inventory

try:
    from ortools.sat.python import cp_model  # noqa: F401
    HAVE_ORTOOLS = True
except Exception:
    HAVE_ORTOOLS = False

TIER_WEIGHT = {"P0": 1000, "P1": 100, "P2": 10, "P3": 1, "OK": 0, None: 0}

# per-exposure-class remediation recipe: (phase, task_type, duration_months, rollback)
RECIPE = {
    "quantum_broken": [
        (1, "externalise-algorithm", 1,
         "revert config to pinned baseline snapshot and reload service"),
        (2, "enable-hybrid-kex", 2,
         "disable PQ group, fall back to classical KEX, reload"),
        (3, "decommission-legacy", 1,
         "re-open legacy listener from snapshot if peers regress"),
    ],
    "quantum_weakened": [
        (1, "increase-parameters", 1,
         "restore previous key size / parameter set from snapshot"),
    ],
    "unknown": [
        (0, "investigate-asset", 1,
         "n/a — investigation only, no production change"),
    ],
}

# A negotiated key-exchange weakness (e.g. static-RSA suites) cannot be
# "externalised" like a source literal — the server simply has to stop
# offering it. Such assets route straight to decommissioning. Selected when
# the matched rule's remediate hint carries action: decommission.
DECOMMISSION_RECIPE = [
    (2, "enable-hybrid-kex", 2,
     "re-enable classical-only suites from snapshot if peers regress"),
    (3, "decommission-legacy", 1,
     "re-open legacy suite from snapshot if peers regress"),
]

# A weak certificate (small key, weak curve, or a forgeable SHA-1/MD5 signature)
# is fixed by REISSUING the certificate: generate a fresh strong key, obtain a
# new certificate signed with SHA-256+ (ideally with a crypto-agile / PQ-ready
# profile), deploy it, then revoke the old one. This is an issuance workflow,
# not a config revert, so it gets its own recipe. Selected when the matched
# rule's remediate hint carries action: reissue.
REISSUE_RECIPE = [
    (1, "reissue-certificate", 2,
     "keep the old certificate installed until the replacement is validated"),
    (2, "deploy-and-revoke", 1,
     "roll back to the previous certificate if the new chain fails validation"),
]


def _recipe_for(asset):
    """Choose the remediation recipe for an asset. Assets whose rule marks
    remediate.action == 'decommission' (negotiated kx weaknesses) skip the
    source-level externalise step and go straight to hybrid + decommission;
    remediate.action == 'reissue' (weak certificates) route to the issuance
    workflow."""
    if isinstance(asset.remediate, dict):
        action = asset.remediate.get("action")
        if action == "decommission" and asset.exposure_class == "quantum_broken":
            return DECOMMISSION_RECIPE
        if action == "reissue":
            return REISSUE_RECIPE
    return RECIPE.get(asset.exposure_class)


@dataclass
class Task:
    id: str
    type: str
    phase: int
    target_asset: str
    target_display: str
    owner: str
    duration_months: int
    target_algorithm: str = ""
    prerequisites: list[str] = field(default_factory=list)
    window: str = "Sat 02:00-05:00, outside quarter-end freeze"
    action: str = ""
    rollback: str = ""
    acceptance: str = ""
    requirement: dict | None = None      # remediation target copied from the asset's rule (for verify)
    weight: int = 0
    start_month: int | None = None


def _acceptance_for(ttype: str, display: str, loc: str, requirement: dict | None = None) -> str:
    if ttype == "enable-hybrid-kex":
        return f"tls_endpoint({loc}).groups includes a PQ hybrid group AND handshake_success >= 0.999"
    if ttype == "externalise-algorithm":
        return f"source_scan finds no hard-coded algorithm literal for {display}"
    if ttype == "decommission-legacy":
        return f"tls_endpoint({loc}) does NOT negotiate any quantum_broken suite"
    if ttype == "increase-parameters":
        req = requirement or {}
        if "require_min_key_length" in req:
            return (f"every remaining occurrence of {display} has "
                    f"key_length >= {req['require_min_key_length']}")
        if "require_algorithm" in req:
            allowed = ", ".join(req["require_algorithm"])
            return f"{display} is replaced by one of: {allowed}"
        return f"asset {display} meets the rule-pack remediation target"
    if ttype == "reissue-certificate":
        req = requirement or {}
        if "require_signature_hash" in req:
            return (f"no certificate remains signed with a weak digest "
                    f"(require {req['require_signature_hash']}+) for {display}")
        if "min_key_length" in req:
            return (f"no certificate key below {req['min_key_length']} bits "
                    f"remains for {display}")
        if "prefer" in req:
            return f"no weak-curve certificate remains for {display}"
        return f"weak certificate {display} has been reissued"
    if ttype == "deploy-and-revoke":
        return f"old weak certificate for {display} no longer served and is revoked"
    return f"asset {display} manually reviewed and dispositioned"


def synthesise_tasks(inv: Inventory) -> list[Task]:
    tasks: list[Task] = []
    n = 0
    for a in inv.assets:
        if a.tier in (None, "OK", "P3") and a.exposure_class in ("pq_ready", "hybrid"):
            continue
        recipe = _recipe_for(a)
        if not recipe:
            continue
        owner = sorted(a.owners())[0] if a.owners() else "unassigned"
        loc = next((o.locator for o in a.occurrences if o.collector == "tls"),
                   a.occurrences[0].locator if a.occurrences else "?")
        prev_id = None
        for phase, ttype, dur, rollback in recipe:
            n += 1
            tid = f"T-{n:03d}"
            requirement = a.remediate if ttype in ("increase-parameters",
                                                     "reissue-certificate",
                                                     "deploy-and-revoke") else None
            t = Task(id=tid, type=ttype, phase=phase,
                     target_asset=a.asset_id, target_display=a.display,
                     target_algorithm=a.algorithm,
                     owner=owner, duration_months=dur,
                     prerequisites=[prev_id] if prev_id else [],
                     action=f"{ttype} for {a.display} at {loc}",
                     rollback=rollback,
                     acceptance=_acceptance_for(ttype, a.display, loc, requirement),
                     requirement=requirement,
                     weight=TIER_WEIGHT.get(a.tier, 1))
            tasks.append(t)
            prev_id = tid
    return tasks


def _list_schedule(tasks: list[Task], capacity: dict, horizon: int) -> dict:
    """Deterministic list scheduling: earliest feasible month respecting
    prerequisites and per-owner monthly concurrency. Returns metadata,
    including whether any task was forced past the horizon (an honest signal
    that the instance is infeasible at this capacity)."""
    per_owner = capacity.get("per_owner_concurrent", {})
    default_cap = capacity.get("default_concurrent", 1)
    by_id = {t.id: t for t in tasks}
    # order by (phase, -weight, id) so urgent items go first
    order = sorted(tasks, key=lambda t: (t.phase, -t.weight, t.id))
    load: dict[tuple, int] = {}   # (owner, month) -> count
    overflow = 0
    for t in order:
        earliest = 0
        for pre in t.prerequisites:
            p = by_id[pre]
            if p.start_month is not None:
                earliest = max(earliest, p.start_month + p.duration_months)
        cap = per_owner.get(t.owner, default_cap)
        m = earliest
        # search for a feasible slot; do not cap the search at the horizon so
        # the caller can see the true finish month
        while True:
            if all(load.get((t.owner, mm), 0) < cap
                   for mm in range(m, m + t.duration_months)):
                break
            m += 1
            if m > horizon * 4:          # guard against pathological loops
                break
        t.start_month = m
        for mm in range(m, m + t.duration_months):
            load[(t.owner, mm)] = load.get((t.owner, mm), 0) + 1
        if m + t.duration_months > horizon:
            overflow += 1
    makespan = max((t.start_month + t.duration_months) for t in tasks) if tasks else 0
    return {"makespan_months": makespan, "over_horizon_tasks": overflow,
            "feasible_within_horizon": overflow == 0}


def weighted_exposure_days(tasks: list[Task]) -> int:
    """Objective value shared by both solvers: sum over tasks of
    weight x start_month x 30. Lower is better (exposure ends sooner for the
    most urgent assets)."""
    return sum(t.weight * (t.start_month or 0) * 30 for t in tasks)


def _cpsat_schedule(tasks: list[Task], capacity: dict, horizon: int,
                    time_limit_s: float = 10.0) -> dict:
    """Exact scheduler: minimise sum(weight x start_month) subject to
    prerequisite ordering and per-owner monthly concurrency (a cumulative
    constraint). The horizon is a soft target: if it cannot be met, the model
    extends the time bound, still minimises weighted start, and reports the
    resulting makespan and how many tasks land past the horizon."""
    from ortools.sat.python import cp_model

    per_owner = capacity.get("per_owner_concurrent", {})
    default_cap = capacity.get("default_concurrent", 1)

    # generous upper bound so the model is always feasible; the objective and
    # the makespan term keep the schedule tight.
    total_months = sum(max(1, int(t.duration_months)) for t in tasks) + horizon
    ub = max(horizon, total_months)

    model = cp_model.CpModel()
    start, end = {}, {}
    intervals_by_owner: dict[str, list] = {}
    for t in tasks:
        dur = max(1, int(t.duration_months))
        s = model.NewIntVar(0, ub - dur, f"start_{t.id}")
        e = model.NewIntVar(dur, ub, f"end_{t.id}")
        iv = model.NewIntervalVar(s, dur, e, f"iv_{t.id}")
        start[t.id], end[t.id] = s, e
        intervals_by_owner.setdefault(t.owner, []).append(iv)

    for t in tasks:
        for pre in t.prerequisites:
            if pre in start:
                model.Add(start[t.id] >= end[pre])

    for owner, ivs in intervals_by_owner.items():
        cap = int(per_owner.get(owner, default_cap))
        model.AddCumulative(ivs, [1] * len(ivs), cap)

    makespan = model.NewIntVar(0, ub, "makespan")
    model.AddMaxEquality(makespan, [end[t.id] for t in tasks]) if tasks else None

    # primary: weighted start (exposure); secondary: makespan, lightly weighted
    # so it never dominates urgency but breaks ties toward compact schedules.
    weighted_start = sum(t.weight * start[t.id] for t in tasks)
    model.Minimize(weighted_start + makespan)

    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = time_limit_s
    # deterministic output: single worker + fixed seed so the same instance
    # always yields the same schedule (the plan artefact must be reproducible).
    solver.parameters.num_search_workers = 1
    solver.parameters.random_seed = 42
    status = solver.Solve(model)
    status_name = solver.StatusName(status)

    if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        for t in tasks:
            t.start_month = int(solver.Value(start[t.id]))
        ms = int(solver.Value(makespan)) if tasks else 0
        over = sum(1 for t in tasks
                   if (t.start_month + max(1, int(t.duration_months))) > horizon)
        return {"status": status_name,
                "objective": solver.ObjectiveValue(),
                "best_bound": solver.BestObjectiveBound(),
                "wall_time_s": round(solver.WallTime(), 3),
                "proven_optimal": status == cp_model.OPTIMAL,
                "makespan_months": ms,
                "over_horizon_tasks": over,
                "feasible_within_horizon": over == 0}
    return {"status": status_name, "objective": None,
            "wall_time_s": round(solver.WallTime(), 3), "proven_optimal": False}


def schedule(tasks: list[Task], capacity: dict, horizon: int,
             solver: str = "auto", time_limit_s: float = 10.0) -> dict:
    """Dispatch scheduling. solver:
      'auto'  -> CP-SAT if OR-Tools is importable, else list scheduling;
      'cpsat' -> force CP-SAT (falls back to list only if OR-Tools is missing);
      'list'  -> force the deterministic heuristic.
    Returns metadata describing what actually ran.
    """
    want_cpsat = solver == "cpsat" or (solver == "auto" and HAVE_ORTOOLS)
    if want_cpsat and HAVE_ORTOOLS:
        meta = _cpsat_schedule(tasks, capacity, horizon, time_limit_s)
        if meta.get("objective") is not None:
            return {"solver": "cp-sat", **meta}
        # only UNKNOWN/model error reaches here now -> heuristic fallback
        lm = _list_schedule(tasks, capacity, horizon)
        return {"solver": "list-scheduling",
                "fallback_reason": f"cp-sat returned {meta.get('status')}", **lm}
    if solver == "cpsat" and not HAVE_ORTOOLS:
        lm = _list_schedule(tasks, capacity, horizon)
        return {"solver": "list-scheduling",
                "fallback_reason": "ortools not installed", **lm}
    lm = _list_schedule(tasks, capacity, horizon)
    return {"solver": "list-scheduling", **lm}


def plan(assessment_cbom: str, capacity_path: str, horizon_months: int,
         out_path: str, solver: str = "auto", time_limit_s: float = 10.0) -> dict:
    inv = Inventory.load(assessment_cbom)
    capacity = yaml.safe_load(open(capacity_path, encoding="utf-8"))
    tasks = synthesise_tasks(inv)
    meta = schedule(tasks, capacity, horizon_months, solver=solver,
                    time_limit_s=time_limit_s)

    doc = {
        "solver": meta["solver"],
        "solver_meta": {k: v for k, v in meta.items() if k != "solver"},
        "horizon_months": horizon_months,
        "task_count": len(tasks),
        "weighted_exposure_days": weighted_exposure_days(tasks),
        "phases": sorted({t.phase for t in tasks}),
        "tasks": [asdict(t) for t in tasks],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True)
    with open(out_path.replace(".yaml", "") + ".json", "w") as f:
        json.dump(doc, f, indent=2)
    return doc
