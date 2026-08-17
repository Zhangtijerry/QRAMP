# QRAMP CI examples

Two ready-to-use GitHub Actions workflows.

## `github-code-scanning.yml` — minimal

Scan, assess, upload SARIF, and fail on any quantum-broken finding. The smallest
useful gate: weak crypto shows up annotated on the exact source lines in the pull
request, and the build fails if a Shor-broken usage is introduced.

## `ci-full-pipeline.yml` — end-to-end

The complete story, in three jobs:

| Job | Runs when | Gates on |
| --- | --- | --- |
| `policy-lint` | every push/PR | rule pack, provider map, VEX, and the manifest alias map are internally consistent (`lint-*`, `--strict`), and the snapshots have not drifted |
| `crypto-scan` | after `policy-lint` | no un-suppressed quantum-broken finding remains; every rule that fired cites a governing standard; reports wrapper coverage (optionally gated via `MAX_WRAPPER_PCT`); when `.qramp/baseline.json` is committed, no *new* exposed asset appears beyond the accepted backlog; uploads SARIF (with VEX suppressions) to the Security tab; reports readiness; publishes a shareable report bundle as an artifact; posts the headline metrics as a PR comment |
| `policy-audit` | pull requests that touch a policy file | the change does not make the real inventory's posture worse (`policy-diff --fail-on-worse`) |
| `gate-summary` | always (after the others) | tabulates every gate's pass/fail into the run **Summary** page and fails the pipeline once if any gate failed |

The design separates three questions that fail independently:

1. **Is the policy well-formed?** — `lint-rules`, `lint-provider-map`,
   `lint-vex`, and `lint-aliases` with `--strict` (warnings fail too), plus
   snapshot regression so a rule or version-gate edit that changes a known
   classification is caught.
2. **Is the code clean?** — the SARIF gate counts error-level results that are
   *not* VEX-suppressed and fails if any remain. A second gate, `provenance
   --cbom … --require-references`, fails if any rule that classified an asset in
   this scan lacks a governing-standard citation, so no un-sourced finding ships.
3. **Does a policy change make things worse?** — `policy-diff` re-evaluates the
   *real* inventory under the base-branch and PR versions of each policy file and
   fails if an asset is promoted to a more urgent tier, newly blocked, or has an
   exception removed.

## One place to see every gate

Each gate step carries an `id` and `continue-on-error: true`, so every gate runs
even when an earlier one failed, and each job exposes its gate outcomes as job
`outputs`. The final `gate-summary` job reads them all and writes one table to the
run's **Summary** page — ✅ / ❌ / ➖ per gate — then fails the pipeline once if any
gate failed. The payoff is that a reviewer sees *all* failing gates at a glance
instead of fixing one, pushing, and discovering the next; the single red check to
require in branch protection is `gate-summary`. (Because the gates use
`continue-on-error`, the individual jobs show green even on a gate failure — the
authoritative pass/fail is `gate-summary`.) On a pull request the same table is
also folded into the QRAMP comment, so the gate matrix sits next to the metrics.

## Running the gates locally

Every gate is just a CLI call, so you can reproduce the pipeline before pushing:

```bash
# policy is well-formed
qramp lint-rules .qramp/rules.yaml --snapshot .qramp/rule-snapshot.json --strict
qramp lint-provider-map .qramp/provider-map.yaml --snapshot .qramp/provider-snapshot.json --strict
qramp lint-vex .qramp/vex.yaml --strict
qramp lint-aliases .qramp/manifest-aliases.yaml --map .qramp/provider-map.yaml \
  --snapshot .qramp/alias-snapshot.json --strict

# scan + assess
qramp scan --source . --config . --certs . --sbom sbom.cdx.json -o cbom.json
qramp assess cbom.json --rules .qramp/rules.yaml --lifetimes .qramp/data-lifetimes.yaml -o assessment.json

# the same hard gate CI uses (exit 1 if any un-suppressed quantum-broken finding)
qramp export assessment.json --format sarif --rules .qramp/rules.yaml \
  --min-level error --vex .qramp/vex.yaml -o gate.sarif
python -c "import json,sys; d=json.load(open('gate.sarif')); \
  n=len([r for r in d['runs'][0]['results'] if 'suppressions' not in r]); \
  print('active:', n); sys.exit(1 if n else 0)"

# provenance coverage gate: every rule that fired must cite a standard
qramp provenance .qramp/rules.yaml --cbom assessment.json --require-references

# readiness as a gate (optional): require >= 40% and no unaddressable blocks
qramp readiness assessment.json --min-readiness 40 --max-unaddressable 0

# wrapper coverage (optional): fail if >40% of mapped packages are wrappers
qramp lint-aliases --cbom cbom.json --max-wrapper-pct 40

# baseline (optional): freeze today's backlog once, then block only new exposure
qramp baseline assessment.json -o .qramp/baseline.json          # run once
qramp baseline-check assessment.json --baseline .qramp/baseline.json

# audit a policy edit against your current inventory
qramp policy-diff assessment.json --kind rules \
  --old .qramp/rules.yaml --new .qramp/rules.next.yaml \
  --lifetimes .qramp/data-lifetimes.yaml --fail-on-worse

# see what an upgrade would do before scheduling it
qramp simulate assessment.json --upgrade openssl=3.5

# render the interactive dashboard (with the two graphs, readiness, VEX status)
qramp report assessment.json --vex .qramp/vex.yaml -o dashboard.html

# assemble the full shareable report site (same as the CI artifact)
qramp bundle assessment.json --rules .qramp/rules.yaml --vex .qramp/vex.yaml \
  --history .qramp/history -o qramp-report      # open qramp-report/index.html
```

## The report artifact

Every `crypto-scan` run publishes a `qramp-report` artifact — the full static
site (dashboard, provenance page, graphs, machine-readable data, and an index).
Download it from the run's *Artifacts* section and open `index.html`; no server
or install is needed, so it can be forwarded to a manager or auditor as-is.

To get the migration-progress page in the artifact, commit past assessed CBOMs to
`.qramp/history/` — the bundle step picks them up automatically and the current
scan becomes the latest point on the trend. A simple pattern is to copy each
release's `assessment.json` into `.qramp/history/<date>.json`.

## The PR comment

On a pull request, the job also posts a short comment with the headline metrics —
urgent (P0/P1) count, quantum-broken/weakened, migration readiness, and, when
`.qramp/history/` exists, the trend since the last scan — plus a link to the full
report artifact. It also assesses the **base branch's code** (holding the current
policy constant) and shows a *change vs base* section: which quantum-broken (🔴)
and quantum-weakened (🟠) assets this PR adds or removes, and whether the net
effect worsens, improves, or merely shifts the posture. The verdict is
severity-weighted, so trading a quantum-broken asset for a quantum-weakened one
(e.g. migrating RSA to AES-128) reads as an improvement rather than a wash — a
reviewer sees the concrete effect of *this* change, not just the absolute numbers.
A collapsible **Gate results** table carries every CI gate's pass/fail, so the
gate matrix sits next to the metrics instead of only on the run Summary page.
Each failing gate links straight to its step's log (the `gate-summary` job reads
the run's jobs via the API and builds a `#step:N:1` anchor), so a red gate is one
click from its cause; the same links appear in the run Summary table.

The comment is built and posted by the `gate-summary` job — the only place all
gate outcomes are known — which downloads the assessment (and base assessment)
that `crypto-scan` uploads as an artifact. A hidden marker
(`<!-- qramp-pr-comment -->`) lets the job find and *update* its own comment on
each push, so the thread does not fill up. This needs `pull-requests: write` in
the job's `permissions`.

Teams can brand the comment and trim it: set the repo/org variables
`PR_COMMENT_TITLE` (the heading), `PR_COMMENT_SUBTITLE` (a company or service name
shown under it), and `PR_COMMENT_COMPACT` (`true` to fold the trend and
recommendation into a collapsible block, keeping the verdict, metrics, change vs
base, and any failing gates prominent). Preview it locally with:

```bash
qramp pr-comment assessment.json --map .qramp/provider-map.yaml \
  --history .qramp/history \
  --base base-assessment.json \     # optional: adds the change-vs-base section
  --gates gates.json \              # optional: adds the gate-results table
  --title "PQC Readiness" --subtitle "Acme Corp · payments" --compact
```

## Tuning the gates over time

- Start with the SARIF gate at `--min-level error` (quantum-broken only), then
  tighten to `warning` (adds quantum-weakened) as the migration progresses.
- Turn `readiness --min-readiness` up as libraries are upgraded; it is a ratchet
  that prevents backsliding.
- To adopt the gates on a codebase with an existing backlog, commit a
  `.qramp/baseline.json` (`qramp baseline assessment.json -o .qramp/baseline.json`)
  so only *new* exposure blocks. Regenerate it smaller as you migrate — the
  `resolved` count in each run tells you when it is safe to shrink; run
  `baseline-check --strict` locally to see stale entries.
- Keep the snapshots (`rule-snapshot.json`, `provider-snapshot.json`,
  `alias-snapshot.json`) under
  review — regenerate them deliberately with `--update-snapshot` when a policy
  change is intended, so an *unintended* change still fails.
