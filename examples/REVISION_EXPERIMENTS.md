# Reproducing the 0.1.1 review evaluation

Use Python 3.12 in an isolated environment and run from the repository root:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[source,solver,validate,versions,dev]"
# Optional: install the exact Python 3.12 dependency snapshot before running.
python -m pip install -r requirements-revision.txt
python -m pytest -q -rs
python scripts/reproduce_revision.py --out revision-results --sensitivity --repeats 3 --time-limit 10
```

The snapshot records the validation environment; the package's broader Python
requirement is not a claim that this exact snapshot supports all Python versions.
No endpoint is contacted by this experiment script. Active PQ handshake
validation needs a compatible TLS environment and is not claimed by these runs.

## Outputs

- `summary.json`: version/checkout/environment, inventory accounting, class/tier
  denominators, task types, readiness and acceptance counts.
- `cbom.json`, `assessment.json`: internal intermediate inventories. Their
  canonical identity and occurrences survive save/load. They are distinct from
  the standard interchange document `cbom.cdx.json`.
- `plan-list.yaml`, `plan.csv`, `verification.json`, `dashboard.html`: the complete
  current plan, scoped results and an offline dashboard.
- `discovery.json`, `discovery.csv`, `challenge-inputs/`: all predictions, labels,
  and source snippets for the new controlled challenge set.
- `scheduling.json`, `schedules/<configuration>/<solver>-<run>.json`: all raw
  schedules, settings, statuses, bounds and the comparison summary. Each schedule
  is checked independently for precedence and per-owner monthly capacity.

The seven scheduling configurations vary capacity, duration, complete-asset task
subsets and graph duplication while preserving dependency chains. Task counts
are measured, not fixed at the obsolete 59/120/240 values. E is weighted task
start delay (30 times the weighted start months); the solver objective also
includes makespan. CP-SAT uses one worker and seed 42, but a wall-clock cutoff
can yield different incumbents across machines, loads and dependency versions.

## Interpretation and limits

The 60-fixture set is specified in `testbed/revision-source-fixtures.json` and
contains six direct positives, two boundary positives and four negatives per
language. Predictions mean at least one source occurrence. The snippets are
static-analysis fixtures; they are not compiled or executed. Labels are fixed
in the committed JSON before detector execution. This is a new author-constructed
set, not independent real-project annotation and not the unavailable original
paper's fixture files. Alias/indirection/name-collision cases remain visible.

Acceptance covers the original target file/endpoint. Renaming/deleting a target,
changing roots/queries, skipping a collector or failing to parse a candidate
prevents an absence-based pass. After intentional moves or deletions, review the
change and regenerate a plan. New locations of a planned asset identity are reported separately and block
overall acceptance; other/new algorithm identities still require a fresh
assessment and baseline/drift review. Replacement co-occurrence
in a file is not proof of equivalent dataflow or unchanged business behaviour.
Certificate hygiene does not prove service deployment, chain authentication or
revocation. Manual obligations remain explicit non-passes in CI.

No original manuscript numbers should be silently reused after these fixes.
The original v0.1.0 tag is retained; archive the revised source and experiment
outputs separately when preparing the revised paper.
