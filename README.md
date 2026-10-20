# QRAMP

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23487117.svg)](https://doi.org/10.5281/zenodo.23487117)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Zhangtijerry/QRAMP/actions/workflows/ci.yml/badge.svg)](https://github.com/Zhangtijerry/QRAMP/actions/workflows/ci.yml)
[Revision demo notebook](examples/QRAMP_demo.ipynb)

**Cryptographic asset inventory and quantum-resistant migration planning.**

QRAMP collects cryptographic evidence from source code, software bills of
materials, X.509 certificates, service configurations and live protocol
endpoints; resolves it into a CycloneDX **cryptographic bill of materials
(CBOM)**; classifies and prioritises each asset with a versioned rule pack and
an explicit Mosca-inequality urgency model; compiles the result into a phased,
dependency-ordered migration plan with explicit ownership, rollback guidance
and acceptance requirements. Operators re-scan after changes and supply the new
inventory to `verify`; checks report pass, fail, deferred, or manual outcomes.

License: MIT · Python ≥ 3.10. Version 0.1.1 was released on 2026-10-20 and is archived at [Zenodo](https://doi.org/10.5281/zenodo.23487117). The [GitHub release](https://github.com/Zhangtijerry/QRAMP/releases/tag/v0.1.1) and DOI identify the released software snapshot; subsequent documentation updates on `main` do not change that archive.

## Version 0.1.1 review fixes

Canonical algorithms and certificate references now survive internal save/load.
Remediation tasks are scoped by owner, collector and file/endpoint; task ids are
stable across inventory reordering. Hashes and offline signatures use replacement
recipes rather than TLS key-exchange tasks. Library capability declarations create
investigation tasks, not claims of observed application use.

Acceptance requires matching collector provenance, scan root, detection queries
and successfully scanned target files. Missing/moved files, skipped collectors,
parse errors and absent legacy provenance are deferred. C and Rust participate in
source checks. Certificate hygiene checks do not prove live deployment or
revocation; those steps require operator evidence. Task acceptance is scoped to
the original target; run a fresh assessment/baseline check to detect other or new
weak uses. A collector remains a bounded static detector, not a proof of absence
of all cryptographic use.

For a complete reproducible run, including the 60-fixture controlled challenge
set and optional seven-configuration scheduling comparison:

```bash
pip install -e ".[source,solver,validate,versions,dev]"
python scripts/reproduce_revision.py --out revision-results --sensitivity
pytest -q
```

Each scheduler run stores its complete schedule, status and bound and independently
checks precedence and capacity. CP-SAT is time-bounded and is not guaranteed to
beat the heuristic. See [revision notes](REVISION_NOTES_zh.md) and
[experiment instructions](examples/REVISION_EXPERIMENTS.md). The challenge set is
new author-constructed evidence, not independent real-project annotation.

## Install

```bash
pip install -e .              # core (Python source, SBOM, certs, configs, TLS)
pip install -e ".[java]"      # + tree-sitter Java source collector
pip install -e ".[source]"    # + tree-sitter Python, Java, Go, Rust, C/C++ source collectors
pip install -e ".[solver]"    # + OR-Tools exact scheduler (optional)
pip install -e ".[java,go,solver]"
```

The tool runs fully without OR-Tools (deterministic list-scheduling fallback)
and without tree-sitter (source collectors with unavailable grammars yield nothing and
record why, so Python-only scanning is unaffected).

## Five-layer architecture

```
COLLECT   source-py · source-java · source-go · source-rust · source-c · sbom · manifests · certs · configs · tls
   │       (plugins, read-only)
MODEL     CryptoAsset ← n × Occurrence  →  CBOM (CycloneDX)
   │       (the same asset seen in Python, Java AND Go resolves to one asset
   │        with three occurrences — cross-language entity resolution)
   │       Component --provides--> CryptoAsset  (library → capability graph)
   │       Certificate --signed_by--> Certificate  (trust chain, weakest link)
   │
ASSESS    versioned YAML rule pack + Mosca X+Y−Z  →  P0–P3 tiers
   │       (lint-rules + snapshot regression + policy-diff on all three policy files)
   │
PLAN      task DAG under prereq/interop/window/capacity  →  schedule
   │       (readiness: ROI-ranked library upgrades that unblock PQC migration)
   │       (simulate: diff the inventory before/after a proposed library upgrade)
   │
REPORT    CBOM · plan · Gantt · interactive HTML dashboard · issues · SARIF · VEX · timeline · DOT/Mermaid · report bundle · PR comment · org dashboard   ↺ verify
```

## Quickstart (against the shipped testbed)

```bash
# 1. authorise the only host the TLS collector may touch
qramp sign-scope testbed/testbed.scope.yaml --key testbed/scope.key

# 2. build the inventory
qramp scan --source testbed/sample-app \
           --sbom   testbed/sample-app/sbom.cdx.json \
           --certs  testbed/certs \
           --config testbed/etc \
           --owners testbed/policy/owners.yaml \
           -o cbom.json

# 3. classify + prioritise
qramp assess cbom.json \
      --rules src/qramp/rules/transition-2024.yaml \
      --lifetimes testbed/policy/data-lifetimes.yaml \
      -o assessment.json

# 4. plan
qramp plan assessment.json --capacity testbed/policy/teams.yaml \
      --horizon 24m -o plan.yaml

# 5. evaluate this supplied scan (unremediated testbed: nonzero exit expected)
qramp verify plan.yaml --against cbom.json --phase 1 --evidence-out evidence.json

# artefacts
qramp report assessment.json -o dashboard.html
qramp export plan.yaml --format issues -o issues.json
qramp export assessment.json --format cyclonedx -o cbom.cdx.json   # standards-compliant CBOM
qramp export assessment.json --format sarif --rules src/qramp/rules/transition-2024.yaml -o qramp.sarif   # GitHub code scanning
qramp diff cbom_before.json cbom_after.json
```

## Task acceptance against refreshed evidence

Run `scan` again after remediation, preserving the scan roots and detection query
versions, and pass that file to `verify`. This command does not run collectors.
Definite retained weaknesses fail; a successful absence-based check additionally
requires complete evidence for its target file. File deletion or a move requires
operator review and replanning, not an automatic pass. A file move inside the root
is also deferred because the old obligation no longer has its original file.

| Task type | Acceptance scope |
|---|---|
| `externalise-algorithm` | No confirmed hard-coded use of the target algorithm in the target source file; indeterminate use is deferred |
| `replace-algorithm` | Target algorithm removed and a configured alternative observed in the same target file; this is file-level co-occurrence evidence, not dataflow equivalence |
| `increase-parameters` | Parameters/replacement satisfy the rule requirement in the target file |
| `enable-hybrid-kex` | Successful authorised active PQ-hybrid probe; passive group observation alone is deferred |
| `decommission-legacy` | Authorised active legacy-refusal probe; modern passive TLS versions alone are insufficient |
| `reissue-certificate` | Parsed replacement file meets supported key/digest/curve hygiene requirement; unsupported profiles are manual |
| `deploy-and-revoke` | Manual evidence required; scan absence does not prove deployment or revocation |
| `investigate-asset` | Manual disposition required |

Results retain `passed` and the `failed` count of all non-passes for existing CI
consumers. New `status` and `status_counts` distinguish `pass`, `fail`, `deferred`
and `manual`. Prerequisites are re-evaluated even when a phase selector hides them;
a task cannot pass while a prerequisite is unaccepted. Non-passes exit with code 2.
Legacy plans without evidence scope must be regenerated before they can pass.
New locations of planned asset identities are reported separately in
`unplanned_target_occurrences`; these block the overall `accepted` verdict and
CLI gate even if the original file-specific task passes. This is not a detector
for every new algorithm: run a fresh assessment for broader inventory drift. An
empty check selection is not an acceptance verdict.

## Scheduling: exact and heuristic, compared

The planner has two interchangeable schedulers behind one dispatcher. Both
respect prerequisites and per-owner concurrency. The reported metric is weighted
task-start delay, E = 30 sum(weight * start_month), not exposure until completion.
CP-SAT minimises sum(weight * start_month) + makespan; the list scheduler uses a
deterministic ready-task heuristic:

- **CP-SAT** (`--solver cpsat`, needs `pip install -e ".[solver]"`) — an exact
  constraint model (OR-Tools) using a cumulative constraint for capacity. It
  proves optimality on small instances and returns the best schedule found
  within `--time-limit` on large ones.
- **List scheduling** (`--solver list`) — a deterministic greedy heuristic,
  always available, used automatically when OR-Tools is absent.

`--solver auto` picks CP-SAT when installed. The single-worker search uses seed
42, but a wall-clock limit does not guarantee the same incumbent across machines
or versions. Inspect solver status, objective, best bound and proven-optimal flag.
The requested horizon is a reporting target; tasks may extend beyond it. Positive
integer capacities and durations and a valid DAG are required. Change-window
strings are metadata, not enforced constraints. Generate current metrics with the
revision reproduction script; the former 90-task/~29% example is obsolete.

```bash
qramp plan assessment.json --capacity teams.yaml --horizon 30m --solver cpsat --time-limit 8
qramp plan assessment.json --capacity teams.yaml --horizon 30m --solver list
```

## Active handshake verification

Two acceptance checks can be confirmed by real handshakes rather than passive
observation, both gated by the same signed scope file and both read-only.

**`enable-hybrid-kex`** with `--active-probe` attempts a real TLS 1.3 handshake
pinned to a post-quantum hybrid group (`X25519MLKEM768` etc.), repeated
`--attempts` times, and passes only at a success rate ≥ 0.999.

**`decommission-legacy`** with `--active-probe` does the inverse: it attempts a
handshake forcing each legacy protocol version (TLS 1.0/1.1, SSLv3) and each
Shor-broken or weak key exchange / cipher (static-RSA key transport, 3DES, RC4,
export), and passes only if the endpoint **refuses every one**. This catches
weaknesses passive TLS-version observation misses — e.g. an endpoint that speaks
TLS 1.2 but still accepts static-RSA key exchange (no forward secrecy,
Shor-broken) is reported as *not decommissioned*.

```bash
qramp verify plan.yaml --against cbom.json --phase 3 \
      --active-probe --scope testbed/testbed.scope.yaml --scope-key testbed/scope.key
```

Both probes report capability limitations explicitly: if a check cannot actually
be performed here (PQ groups unsupported by the local OpenSSL; endpoint
unreachable; none of the legacy parameters offerable), the result is **deferred
and fails closed** with the specific reason — without treating unavailable probes as successful. Like the TLS
collector, the probes are read-only (standard handshakes, no application data,
no exploitation) and run only against hosts in the HMAC-signed scope file.

## Standards-compliant CBOM export

`qramp export <cbom-or-assessment> --format cyclonedx` emits a
**CycloneDX 1.6 Cryptographic Bill of Materials** that validates against the
official JSON schema and is consumable by any CycloneDX tool (cyclonedx-cli,
Dependency-Track, IBM CBOMkit). QRAMP's internal model is mapped onto the spec:
each asset becomes a `cryptographic-asset` component with `cryptoProperties` —
algorithms carry `algorithmProperties` (spec `primitive` enum, e.g.
`block-cipher`, `pke`, `key-agree`, `ae` for AEAD; `mode`, `curve`,
`parameterSetIdentifier`, `cryptoFunctions`, `classicalSecurityLevel`, and a
`nistQuantumSecurityLevel` category), while protocols carry
`protocolProperties` (type, version). Findings map to `evidence.occurrences`
(location + line). QRAMP-specific enrichment — exposure class, Mosca tier,
remediation plan, owners, tags — is preserved as standard `properties` under a
`qramp:` namespace, so nothing is lost and schema validity is retained. The
export is round-trip verified: the official `cyclonedx-python-lib` parses it
into its object model and re-serializes it.

## SARIF export for GitHub code scanning

`qramp export <assessment> --format sarif --rules <pack> -o qramp.sarif` emits a
SARIF 2.1.0 document, validated against the official SARIF schema. Because the
tree-sitter and config collectors record precise `path:line` locators, each
weak-crypto usage becomes a SARIF *result* pinned to the exact source line —
uploaded via `github/codeql-action/upload-sarif`, MD5 at `payments.py:10` or a
static-RSA cipher list at `nginx.conf:5` appears as an annotation right in the
pull request. The rule pack's rules become SARIF *reportingDescriptor* objects
(help text, remediation target, default severity), and exposure maps to level:
quantum-broken → `error`, quantum-weakened → `warning`, everything else →
`note`, with a `security-severity` score derived from the Mosca tier so GitHub
buckets the alerts. Certificate findings map to their file with no line; active
TLS probe findings (`host:port`) become logical locations so nothing is dropped.

Each result carries a partial fingerprint keyed on the asset identity and file
but deliberately **not** the line number, so GitHub tracks a finding across
commits even when edits shift lines. `--min-level error` drops everything below
error for a CI gate; a full `.github/workflows` example that uploads annotations
and optionally fails the build on any quantum-broken finding is in
`examples/github-code-scanning.yml`.

## VEX: accepted exceptions that quiet the gate

A scan flags every weak-crypto usage, but many are not exploitable in a given
deployment — the algorithm is only a non-security cache key, the path is
unreachable, a compensating control is already in place, or a migration is
scheduled and accepted for now. A **VEX** document records those exceptions as
versioned, auditable data so the CI gate and the dashboard stop flagging what has
already been triaged, without silently editing the rule pack.

Each statement targets a cryptographic asset by its stable `asset_id` (optionally
narrowed to one locator) and gives a status from the standard VEX vocabulary
(`not_affected`, `affected`, `fixed`, `under_investigation`) with a required
justification for `not_affected`. `qramp lint-vex` static-checks the document
(unknown status, missing justification, non-standard justification, and — with
`--cbom` — statements that target an asset not in the inventory).

```bash
qramp lint-vex vex.yaml --cbom assessment.json           # validate exceptions
qramp export assessment.json --format sarif --vex vex.yaml -o q.sarif   # suppress in SARIF
qramp export assessment.json --format vex --vex vex.yaml -o openvex.json                 # OpenVEX
qramp export assessment.json --format vex --vex vex.yaml --vex-format cyclonedx -o vex.json
```

Applying VEX to a SARIF export adds a native `suppressions[]` entry to each
accepted finding — GitHub shows those as dismissed rather than re-alerting on
every run, so a gate that counts only un-suppressed errors stops failing on
triaged risk (in the testbed, active error findings drop from 57 to 50). The same
exceptions export as a standalone **OpenVEX** document or as a CycloneDX
`vulnerabilities[]` array (with the OpenVEX justification vocabulary mapped to
CycloneDX's `analysis.justification`) that embeds in the CBOM and stays
schema-valid.

## Baseline: accept the existing backlog, block only what's new

A VEX statement says "we assessed this and it's accepted for a stated reason"; a
**baseline** says something different — "this is pre-existing exposure we have not
migrated yet." When a team first turns a hard gate on, the codebase usually
already contains a pile of quantum-broken crypto, so the gate would be red on day
one and could never be enabled. `qramp baseline assessment.json -o baseline.json`
freezes today's exposed assets as an accepted backlog; `qramp baseline-check
assessment.json --baseline baseline.json` then fails only when a **new** exposed
asset appears that is not in the baseline — existing entries do not block. It
reports three counts: `new` (blocks), `accepted` (baselined, allowed), and
`resolved` (baselined but no longer exposed — the backlog shrank). As the
migration progresses the baseline is regenerated smaller, ratcheting the
acceptance down; `--strict` fails when stale entries remain, to force that.
Assets are matched by their stable `asset_id`, so the baseline survives rescans
and reorderings. `--exposure` selects which classes are baselined (default
`quantum_broken`; add `quantum_weakened` to freeze that backlog too).

## Importing third-party CBOMs

Because QRAMP speaks standard CycloneDX both ways, it can also **consume** a
CBOM produced by another tool:

```bash
qramp import vendor.cdx.json -o vendor-inventory.json           # parse a foreign CBOM
qramp import vendor.cdx.json --merge qramp-cbom.json -o all.json  # fold it into a QRAMP scan
qramp diff qramp-cbom.json vendor-inventory.json --detailed     # coverage gaps + conflicts
```

Import inverts the spec mapping (`block-cipher` → symmetric-cipher, `pke` →
pk-encryption, `key-agree` → key-agreement, `ae` → symmetric-cipher with an
AEAD mode, and so on) and canonicalises free-form component names
(`SHA512withRSA` → an RSA signature). A QRAMP-produced BOM carries canonical algorithm identity in `qramp:`
properties, while a foreign BOM falls back to heuristic name parsing of standard
fields. Import adds imported-tool provenance; it is not a lossless replacement
for native per-occurrence evidence or collector coverage. Generate a fresh native
scan before task acceptance.
Every imported occurrence is tagged with its provenance (`source:<tool>`).

`--merge` performs cross-tool **entity resolution**: an asset that QRAMP and the
imported tool both found collapses onto one asset carrying evidence from both,
and a local assessment is never overwritten by imported classifications.
`diff --detailed` reconciles two inventories, reporting assets only one tool
saw (coverage gaps) and assets both saw but classified differently
(classification conflicts). The merged inventory re-exports to schema-valid
CycloneDX, so QRAMP can act as a reconciliation hub across a toolchain.

## Dependency graph: which library provides which capability

An SBOM lists the libraries a system ships; a provider map (versioned data,
`data/provider-map.yaml`) states which cryptographic capabilities each library
provides (OpenSSL → RSA, ECDH, AES; libsodium → X25519, Ed25519; and so on).
The map is **version-aware**: a capability may be gated on the component version
(PEP 440 / comparator syntax such as `">=3.5"`), so `[email protected]` resolves to
ML-KEM and ML-DSA while `[email protected]` does not — the same library name means
different capabilities by version. Each capability carries a confidence in
`[0,1]`. QRAMP records the resolved capabilities as first-class **software
components** with `provides` edges to the crypto assets, and exports them as a
CycloneDX `dependencies` graph (`{ref, provides: [...]}`) alongside the
`library` components — schema-valid and round-trippable.

Producing a CycloneDX SBOM by hand is friction, so QRAMP can **auto-discover**
components straight from the package manifests a project already has. `qramp scan
--manifests` walks the source tree for `package-lock.json`, `requirements.txt`,
`go.mod`/`go.sum`, `pom.xml`, and `Cargo.lock`/`Cargo.toml`, extracts the
declared dependencies, and feeds the crypto-relevant ones through the same
version-aware provider map — no hand-written SBOM required.

```bash
qramp scan --source . --manifests -o cbom.json    # discover from the source tree
qramp scan --manifests ./services -o cbom.json    # or an explicit directory
```

The parsers are dependency-free and lenient — an unparseable lock file
contributes what it can rather than failing the scan — and vendored trees
(`node_modules`, `vendor`, `target`) are skipped. Package names are normalised to
the provider-map key across ecosystems (the Maven artifact `bcprov-jdk18on` and
the native `libssl` both resolve to their underlying library). Crucially, a
**wrapper/binding** package whose version does not track the underlying library —
`pyOpenSSL` 24.x wraps whatever OpenSSL is installed, the `openssl-sys` crate
binds an arbitrary build — is resolved *fail-closed*: its version does not drive
the provider map's gates, so it cannot wrongly claim ML-KEM just because
"24.0.0 ≥ 3.5". Such components are recorded at their baseline capabilities and
marked `~wrapper`, keeping the version-gated PQC attribution honest. Manifest
discovery composes with an explicit `--sbom` and the source scanners, so a scan
can draw components from all of them at once.

The package-name normalisation is itself **versioned data**
(`data/manifest-aliases.yaml`), not code, so a team can add their own ecosystem
packages the same way they extend the rule pack or provider map — each alias maps
a `package` to a provider-map `component`, with `tracks_version: false` for
wrappers. `qramp lint-aliases` static-checks it (missing fields, a non-boolean
wrapper flag, duplicate packages, and — against a provider map — aliases pointing
at a component the map does not define, which could never resolve), and a
resolution snapshot freezes each `package → (component, tracks_version)` mapping
so a typo, a re-target, or a wrapper flag flipped the wrong way (which would let a
wrapper wrongly drive version-gated resolution) is caught as a regression. A
custom map is supplied per scan with `--alias-map`.

```bash
qramp lint-aliases                                # check the built-in map
qramp lint-aliases my-aliases.yaml --map map.yaml --strict
qramp lint-aliases my-aliases.yaml --snapshot alias-snapshot.json               # regression
qramp lint-aliases my-aliases.yaml --snapshot alias-snapshot.json --update-snapshot
qramp lint-aliases --cbom assessment.json --max-wrapper-pct 40    # wrapper coverage gate
qramp scan --manifests . --alias-map my-aliases.yaml -o cbom.json
```

Given a scan, `lint-aliases --cbom` reports the **wrapper coverage** of the
packages it discovered — what fraction of the mapped packages resolve through
wrappers whose version does not drive capability gates. A high share means
version-gated capabilities are withheld for much of the dependency surface, so
the PQC assessment is conservative and may under-report real readiness (e.g.
pyOpenSSL over an OpenSSL 3.5 that does ship ML-KEM). `--max-wrapper-pct` turns
this into a gate that fails when the wrapper share exceeds the threshold.

```bash
qramp resolve-provider openssl 3.5.0    # capabilities OpenSSL 3.5 provides (incl. PQC)
qramp resolve-provider openssl 1.1.1    # older OpenSSL: no post-quantum
qramp lint-provider-map                 # static-check the built-in map
qramp lint-provider-map map.yaml --snapshot snap.json   # + resolution regression
```

Version resolution fails closed: a version-gated capability is only attributed
when the SBOM version clearly satisfies the gate (an unknown or unparseable
version withholds gated capabilities rather than guessing). `packaging` is used
for correct PEP 440 semantics when present, with a built-in comparator parser as
a fallback. `lint-provider-map` mirrors the rule-pack linter — it flags bad
confidence values, invalid version constraints, unknown primitives, duplicate
components, and non-canonical algorithm spellings, and a resolution snapshot
guards against accidental version-gate edits (lowering OpenSSL's PQC gate to
`>=3.0` would wrongly attribute ML-KEM to 3.0.x — the snapshot catches it).

That graph answers the migration question *"if I swap this library, which
crypto assets are affected?"*:

```bash
qramp impact assessment.json --list                 # every library and what it provides
qramp impact assessment.json --component openssl    # what breaks if OpenSSL is removed
qramp impact assessment.json --algorithm rsa        # which libraries provide RSA
```

`--component` splits the provided assets into **uniquely provided** (they would
have no remaining provider — a genuine capability loss) and **still available**
(another library also ships them). For example, removing OpenSSL from the
testbed uniquely loses AES-256 and ECDH, but RSA survives because `cryptography`
also provides it — so an RSA migration cannot be completed by dropping one
library alone. Exposure classifications flow through, so the impact view shows
which of the affected capabilities are quantum-broken.

## Migration readiness: which upgrade clears the most risk

The version-aware provider map knows which library versions ship post-quantum
capabilities (OpenSSL gains ML-KEM/ML-DSA at 3.5, BouncyCastle at 1.78); the
dependency graph knows which libraries are deployed and at what version.
`qramp readiness assessment.json` combines them to score how ready the stack is
to migrate and to rank the upgrades that would help most.

```bash
qramp readiness assessment.json           # score + ROI-ranked upgrade advice
qramp readiness assessment.json --json    # machine-readable report
```

The core concept is *migration-blocked*: a quantum-broken key-agreement or
signature asset can only move to PQC if some deployed library provides the
quantum-safe replacement primitive (key-agreement → ML-KEM, signature → ML-DSA).
If none does, the asset is blocked and the fix is a **library upgrade**, not a
code change alone. Readiness is the share of PQC-migration assets that already
have a deployable replacement; when it's low, the tool reports the upgrades that
would unblock the rest, ranked by an ROI proxy — weighted risk cleared (P0 = 8,
P1 = 4, …) divided by a coarse upgrade distance, so a small version bump that
clears several P0s ranks above a major jump that clears a few P3s. A typical
line: *OpenSSL 3.0.13 → 3.5 unlocks ML-KEM and ML-DSA, unblocking 20 assets
(P2×17, P3×3)*. Hashes and symmetric ciphers are excluded from the score because
they are Grover-affected, not blocked on a PQC capability, and when a PQC library
such as liboqs is already deployed the score is 100% with no upgrade
recommended — the replacement is present and the remaining work is in code.

Where `readiness` ranks the upgrades worth considering, `qramp simulate` answers
*"if we actually bump OpenSSL to 3.5, what changes?"* before anyone touches a
manifest:

```bash
qramp simulate assessment.json --upgrade openssl=3.5
qramp simulate assessment.json --upgrade openssl=3.5 --upgrade bouncycastle=1.78 --json
```

It re-resolves the provider map at the proposed versions and diffs against today,
keeping two effects distinct so the benefit is never overstated: the **capability
delta** (OpenSSL 3.5 *gains* ML-KEM/ML-DSA; an older 1.0.x → 1.1.x *drops* SSLv3)
and the **migration unblocking** (broken key-agreement/signature assets that
become migratable because a PQC replacement is now deployable — reported as
"unblocked", never "resolved", since the code still has to switch). A run reports
the readiness shift (`0% → 100%`), the blocked-asset change (`20 → 0`), and the
tier breakdown of what gets unblocked. The simulation is side-effect free — it
works from the provider map and current versions without mutating the inventory —
and it validates the request, flagging a downgrade or an un-deployed component
rather than silently doing nothing.

## Certificate trust chains: the weakest link

The same `dependsOn` edge that links a library to its capabilities links a
certificate to the CA that issued it. The cert collector models each
certificate as a node (subject, issuer, CA flag, validity, weak tags) and
resolves the issuer→subject links across the scanned set, so a leaf points at
its signing CA. A certificate is only as trustworthy as the weakest cert above
it, so QRAMP walks each leaf's chain to the root and reports the weakest link:

```bash
qramp chain assessment.json              # every leaf's chain
qramp chain assessment.json --weak-only  # only chains with a problem
qramp chain assessment.json --leaf api   # one leaf by subject substring
```

The headline case this catches is a **strong leaf under a weak CA**: a
certificate with a 2048-bit key and a SHA-256 signature looks clean on its own,
but if it was issued by a CA that still signs with SHA-1, the whole chain is
forgeable. Per-certificate analysis misses this; the chain walk flags it as
`chain broken by <CA>`. Certificates export as CycloneDX `certificate`
asset-type components with `certificateProperties` (subject, issuer,
signatureAlgorithmRef, subjectPublicKeyRef) and the trust chain as `dependsOn`
edges — schema-valid and round-trippable.

## What the rule pack classifies

The shipped pack (`transition-2024.3`) covers the standardised post-quantum
schemes (ML-KEM, ML-DSA, SLH-DSA, FN-DSA → `pq_ready`; classical+PQ hybrids such
as `X25519+ML-KEM-768` and X-Wing → `hybrid`) and the classical schemes Shor or
Grover breaks. Beyond the obvious RSA/ECC/DH, three areas get specific coverage:
**non-standardised PQ** (FrodoKEM, BIKE, HQC, Classic McEliece) is flagged
`quantum_weakened` — usable as a hedge, but not a FIPS-approved KEM on its own;
**sub-256-bit elliptic curves** (secp160/192/224 and the Brainpool equivalents)
hit dedicated `weak-curve-*` rules that call out the *classical* weakness on top
of the quantum one; and **lightweight cryptography** is split by standing — the
NIST SP 800-232 winner ASCON (and ASCON-Hash) is `pq_ready`, legacy 64-bit-block
ciphers (PRESENT, PRINCE, KATAN) are `quantum_broken`, and unstandardised ones
(Speck, Simon, GIFT) are `quantum_weakened`. Because it is first-match-wins data,
a certificate tagged with a weak curve still routes to the cert-hygiene rule
(reissue) rather than the broad code-usage rule — a distinction the snapshot
locks in.

## Provenance: every rule cites its standard

A classification is only defensible if you can point to *why*. Alongside the
human-readable `why`, every rule carries `references` — the governing standard
that justifies the call (`{standard, section?, note?, url?}`), e.g. ML-KEM cites
FIPS 203, a disallowed SHA-1 signature cites NIST SP 800-131A Rev.2 §9 and RFC
9155, a weak DH group cites RFC 7919 and the Logjam CVE. The citations flow onto
each asset, into the CBOM, and through to the outputs: SARIF rule descriptors
carry them in the help text, a structured `properties.references` array, and
`standard/*` tags, and the dashboard shows them on hover over an asset's exposure.
A finding discovered from a package manifest additionally carries an
`aliasResolution` property (package, ecosystem, component, and wrapper/unmapped
flags) with `discovery/manifest`, `discovery/wrapper` tags, so the traceability of
an SBOM-discovered component is visible in the code-scanning view too.

`qramp provenance` prints the audit table — rule → class → governing standards —
as text, Markdown, or JSON, and `--cbom` narrows it to the rules that actually
fired, with occurrence counts, so a report can show exactly which standards back
the findings in *this* scan:

```bash
qramp provenance --format markdown                    # the whole pack, as a table
qramp provenance --format json --cbom assessment.json # only rules that fired, with counts
```

`qramp lint-rules` checks the provenance too: a rule with no `references` is a
warning (add the standard so the classification is auditable), and a malformed
citation — not a list, a missing `standard`, a non-http URL — is flagged, so the
audit trail cannot silently rot. For a hard CI gate, `qramp provenance
--require-references` exits non-zero when any rule lacks a governing-standard
reference; scoped to a scan with `--cbom` it checks only the rules that actually
classified an asset, so an un-sourced classification cannot ship while an unused
rule does not block the build:

```bash
qramp provenance --require-references                              # whole pack
qramp provenance --cbom assessment.json --require-references       # only fired rules
```

## Testing the rule pack itself

The rule pack is editable YAML consumed with **first-match-wins** semantics, so
rule order silently decides outcomes — which makes two editing mistakes easy and
invisible. `qramp lint-rules` guards against both:

```bash
qramp lint-rules rules/transition-2024.yaml                       # static checks
qramp lint-rules rules/transition-2024.yaml --snapshot snap.json  # + regression
qramp lint-rules rules/transition-2024.yaml --snapshot snap.json --update-snapshot
qramp lint-rules rules/transition-2024.yaml --strict              # warnings fail CI too
```

Static analysis reads the match predicate directly. It reports **errors**
(unknown class, duplicate id, missing class, an impossible key-length range, an
unknown match key), **warnings** — most importantly **unreachable rules**: a
rule that can never fire because an earlier rule matches a superset of its
conditions (detected by a subsumption check over the primitive/algorithm/params
sets, key-length ranges, and intersection-semantics tags) — and **info**-level
ambiguous overlaps where two rules can match the same asset with different
classes and order alone decides.

Snapshot regression freezes a set of known assets and their expected
classification *and firing rule*, so an edit shows exactly what changed. It
catches subtle regressions the class alone would miss: if reordering makes a
weak-key RSA certificate classify via `rsa-broken` (quantum_broken) instead of
`weak-cert-key` (quantum_weakened + reissue), the snapshot flags it and the
command exits non-zero — the same class, but the wrong rule and a lost
remediation. Run it in CI to make policy edits safe.

## Auditing a policy change against the real inventory

`lint-*` and the snapshots ask "is the new policy internally consistent?"
against synthetic fixtures. `qramp policy-diff` asks the complementary question —
"what would the new policy do to *the assets we actually have*?" — by
re-evaluating a real assessed CBOM under two versions of a policy file and
reporting the concrete deltas. It covers all three policy inputs:

```bash
qramp policy-diff assessment.json --kind rules \
  --old rules.yaml --new rules.next.yaml --lifetimes lifetimes.yaml --fail-on-worse
qramp policy-diff assessment.json --kind provider-map --old map.yaml --new map.next.yaml
qramp policy-diff assessment.json --kind vex --old vex.yaml --new vex.next.yaml
```

For the **rule pack** it lists every asset whose exposure class, firing rule, or
Mosca tier changes and shows the aggregate tier-distribution shift — so a stricter
edit that repromotes an AES-128 usage from P3 to P2, or a new rule that shadows an
old one and silently drops its remediation, is visible on the real asset, not a
fixture. For the **provider map** it reports which assets flip migration-blocked
status: lowering OpenSSL's PQC gate from `>=3.5` to `>=3.0` would suddenly claim
the deployed 3.0.13 provides ML-KEM and unblock assets it cannot actually
protect — the diff surfaces that. For **VEX** it shows which assets gain, lose, or
change a suppression. `--fail-on-worse` exits non-zero when a change promotes an
asset to a more urgent tier, newly blocks one, or removes a suppression, so a
policy pull request can gate on "does this make our posture worse?". The
evaluation is side-effect free — each side runs on a freshly loaded copy — and
complements the snapshot regressions to form a full policy-change audit trail.

## The whole thing as a CI gate

Every gate above is a CLI call with a meaningful exit code, so they compose into
one pipeline. `examples/ci-full-pipeline.yml` is a complete GitHub Actions
workflow in three jobs that fail independently: `policy-lint` checks that the
policy files — rule pack, provider map, VEX, and the manifest alias map — are
internally consistent (`lint-*` with `--strict`, plus snapshot regression);
`crypto-scan` scans the repo, uploads SARIF (with VEX suppressions)
to the Security tab, fails on any un-suppressed quantum-broken finding, gates on
provenance coverage (every rule that fired must cite a standard), publishes the
shareable report bundle (dashboard, provenance page, graphs, data) as a
downloadable `qramp-report` artifact, and — on a pull request — posts (from the
`gate-summary` job) the headline metrics (urgent count, readiness, trend), a
severity-weighted *change vs base* section listing which quantum-broken and
quantum-weakened assets this PR adds or removes, and a collapsible gate-results
table, as a comment so the concrete effect and gate matrix show up in review (the
comment's title, a branding subtitle, and a compact layout are configurable, and
each failing gate links to its CI step log); and
`policy-audit` runs on pull requests that touch a policy file, re-evaluating the
real inventory under the base and PR versions with `policy-diff --fail-on-worse`
so a change that promotes an asset to a more urgent tier, newly blocks one, or
removes an exception blocks the merge. `readiness --min-readiness` /
`--max-unaddressable` add an optional ratchet that fails when migration progress
slips below a threshold, and `lint-aliases --cbom --max-wrapper-pct` optionally
fails when too much of the dependency surface resolves through wrappers (set the
`MAX_WRAPPER_PCT` repo variable to enable it). A committed `.qramp/baseline.json`
turns the scan into a ratchet: `baseline-check` blocks only *new* exposed crypto,
letting a team enable the gate mid-migration without the existing backlog failing
every PR. A final `gate-summary` job
tabulates every gate's pass/fail into the run's Summary page and fails the
pipeline once if any failed, so a reviewer sees all failing gates at a glance
rather than opening each step's log. `examples/README.md` shows the local
equivalents so the gates can be reproduced before pushing, and
`examples/github-code-scanning.yml` is a minimal single-job version.

## Tracking progress across scans

A single CBOM is a snapshot; a migration is a trend. `qramp timeline` reads a
series of assessed CBOMs, orders them by their scan timestamp (restored from each
CBOM's `metadata.timestamp` on load), and reports the trajectory — so a team can
show that the P0/P1 count is falling and a manager can see the migration's ROI as
a curve rather than a point.

```bash
qramp timeline scans/*.json --series P0,P1 --html progress.html
qramp timeline scans/ --min-improvement 1      # CI ratchet: fail if no progress
```

Point it at a list of CBOMs or a directory and it prints the headline trend
(urgent P0+P1 count first → last, quantum-broken change, net assets remediated
over the window) and the between-scan deltas, attributing each drop to the
specific assets that were remediated by reusing the stable asset-identity diff.
`--svg` writes a deterministic trend chart (one line per tier, falling lines =
progress) and `--html` a standalone progress report with the chart, headline
numbers, and per-scan tables — a management-friendly artefact. `--min-improvement
N` turns it into a CI ratchet that fails if the urgent count did not fall by at
least N since the first scan, so a release cannot regress migration progress.

## HTML dashboard: the two graphs at a glance

`qramp report assessment.json -o dashboard.html` renders a self-contained static
HTML file — no server, no external libraries, only a few lines of inline vanilla
JavaScript — that draws both of QRAMP's graphs as inline SVG node-edge diagrams
alongside the asset table, a migration-readiness panel, and light interactivity.

The **dependency graph** lays libraries out on the left and the cryptographic
capabilities they provide on the right, with `provides` edges between them.
Capabilities are coloured by exposure (red quantum-broken, amber
quantum-weakened, green PQ-ready); a capability provided by more than one library
is drawn with a thicker blue edge and marked `shared × N`, so a capability that
survives dropping one library is obvious. The **certificate trust chains** draw
each leaf → issuer → root as a left-to-right tree, colouring nodes by weakness
and labelling the weakest link — a strong leaf under a SHA-1 CA shows a green
leaf pointing at a red CA tagged `weakest link`, making the chain problem visible
at a glance. A **migration-readiness panel** shows the readiness percentage with
a bar and the ROI-ranked upgrade recommendations inline.

The dashboard is interactive without a server: **filter chips** show/hide table
rows by tier and exposure (combined with AND), and **hovering** a capability node
in the dependency graph highlights the matching inventory row (and vice versa),
because each graph node and table row share the asset's stable id. Both graphs
use deterministic column layout (no physics), so the output is reproducible and
diff-friendly, and each degrades to an empty-state note when its data is absent.

Pass `--vex exceptions.yaml` and the table reflects triage: assets an accepted
exception covers are greyed with a strikethrough, a **Status** column shows the
VEX justification (with the free-text detail on hover), and a **hide N
suppressed** toggle collapses them so what remains is the un-triaged risk. The
toggle only appears when there is something to hide, and the styling makes it
obvious at a glance which findings a human has already reviewed versus which
still need attention.

When SBOM components are present, the dashboard also embeds an **upgrade
simulation** panel driven by the same `simulate` engine. QRAMP precomputes the
before/after for each candidate upgrade (and an "apply all") at render time and
embeds the results as a small JSON blob, so picking an upgrade from the dropdown
instantly re-renders the migration-blocked count, the readiness percentage, how
many assets it newly unblocks, and a per-tier bar chart that shrinks against the
current baseline — all client-side, no server. A team can see *"upgrade OpenSSL
to 3.5 → 23 blocked becomes 0, readiness 0% → 100%"* by clicking, and the panel
disappears when there is no applicable upgrade (the deployed library already
ships the capability).

Passing `--history` with one or more earlier assessed CBOMs (or a directory of
them) adds a **migration-progress** panel at the top of the dashboard: the
current scan becomes the latest point in a trend chart of the P0/P1/P2 counts
over time, with a headline line (trend, urgent-count change, net assets
remediated) — so progress tracking and the current state sit in one view rather
than in a separate report.

## Exporting the graphs as text

The dashboard draws the dependency graph and the trust chains as inline SVG, but
for a Markdown doc, a wiki, or a design record — or to let a real layout engine
handle a large graph — `qramp graph` emits the same two graphs as Graphviz DOT or
Mermaid text.

```bash
qramp graph assessment.json --which dependency --format dot -o deps.dot
qramp graph assessment.json --which chain --format mermaid   # to stdout
```

Both notations read the same `provides` and `signed_by` edges the SVG renderers
use, so the text output is the same graph. Nodes keep the stable identity used
across the tool (library key, `asset_id`, cert `bom_ref`), exposure and weakness
colouring carries across as DOT fill colours and Mermaid `classDef`s, shared
capabilities are marked, and the certificate weakest-link is highlighted (a thick
black outline in DOT, a dedicated class in Mermaid). The DOT output renders with
`dot -Tsvg`, the Mermaid embeds directly in a GitHub Markdown ```` ```mermaid ````
block, and both degrade to a valid empty-state graph when there is nothing to
draw.

## One shareable report for stakeholders

A manager or auditor wants one thing to open, not a folder of loose files.
`qramp bundle` assembles a self-contained static site: an `index.html` landing
page with the headline numbers (urgent P0/P1 count, inventory size, migration
readiness with the top upgrade) and links to every artefact, the interactive
dashboard and the migration-progress report as their own pages, a **provenance
page** that traces every finding to its governing standard, the two graphs as
downloadable DOT/Mermaid text under `graphs/`, and the machine-readable exports
(CycloneDX CBOM, SARIF, `provenance.json`, a `summary.json`) under `data/`.

```bash
qramp bundle assessment.json -o acme-pqc-report \
  --history scans/ --vex exceptions.yaml --rules src/qramp/rules/transition-2024.yaml \
  --title "Acme Corp — PQC Readiness"
# open acme-pqc-report/index.html, or zip the directory and send it
```

The provenance page groups the rules that actually fired in this scan by exposure
class and, for each, shows the rationale, the occurrence count, and the FIPS /
NIST SP / RFC / CVE citations that justify the classification — so the deliverable
an auditor receives already contains the standards documentation, not just the
findings. It is built from the rule pack's `references` when `--rules` is given,
and falls back to the citations each asset carries otherwise, so even a bundle
built from a CBOM alone documents its provenance. When the scan discovered
components from package manifests, the page also carries an *SBOM discovery* table
tracing each package to the library component it resolved to through the alias
map, flagging wrappers (whose version-gated capabilities are withheld) and
unmapped packages — so the traceability of a discovered component matches that of
a rule classification.

Every artefact reuses the existing generators — the dashboard, the timeline
report, the graph exporters, the CycloneDX and SARIF serialisers, the provenance
table — so the bundle is a composition that stays consistent with what the
individual commands produce. It degrades gracefully: no `--history` simply omits
the progress page, no fired rules omits the provenance page, and a scan with no
components or certificates still produces a valid index and empty-state graphs.
There is no server and no external asset, so the whole directory can be zipped and
handed over as-is.

## Rolling many repos up into an org dashboard

For an organisation running QRAMP across many repositories, `repo-card` emits a
compact per-repo posture card — the metrics it already computes plus its CI gate
outcomes — and `org-dashboard` aggregates a directory of cards into one static,
self-contained HTML page:

```bash
# each repo, at the end of its run:
qramp repo-card assessment.json --name "$GITHUB_REPOSITORY" \
  --map .qramp/provider-map.yaml --gates gates.json \
  --url "$RUN_URL" -o card.json
# a central job, over all collected cards:
qramp org-dashboard cards/ -o dashboard.html --title "Acme Corp — PQC migration"
```

The dashboard leads with org-level roll-ups (repositories, how many have failing
gates or urgent assets, total quantum-broken, median readiness) and a sortable
table of every repo — worst first — showing urgent/broken/weakened counts,
readiness, gate status (with the failing gate names on hover), and last scan,
each linking back to its run. Like the report bundle it is one file with inline
vanilla JS and no external assets, so it publishes straight to Pages;
`examples/org-dashboard.yml` shows a scheduled workflow that collects the cards
and deploys the page.

## Safety

The TLS collector performs only standard, read-only handshakes. It refuses to
run against any host absent from an **HMAC-signed scope file**, and it aborts
before sending a single packet if that signature is invalid. No exploitation,
credential testing or fault injection is implemented.

## Extending

Add a collector for a site-specific technology (HSM, code-signing pipeline,
proprietary config) by registering it under the `qramp.collectors` entry point —
no fork required. Rule packs and the SBOM provider map are versioned *data*, not
code.

The source collectors (Python, Java, Go, Rust, C/C++) are query-driven: **which AST shapes
count as crypto call sites** is declared in `.scm` tree-sitter query files under
`collectors/queries/`, versioned alongside the code. The Python module for each
language is a thin interpreter that turns query matches into normalised assets;
the structural detection itself is data you can review and diff. Each scan
records the `query_hash` of the `.scm` file it used into the CBOM metadata, so a
finding can be traced to the exact detection-rule version that produced it. To
teach a collector a new call shape, edit the `.scm`; to teach it a new algorithm
mapping, edit the interpreter's tables.

The five source collectors cover two different call idioms, which the same
engine handles uniformly. Python/Java/Go/Rust use scoped calls where a receiver
names the algorithm family (`Cipher.getInstance("DES/...")`, `Md5::new()`). C
and C++ are name-encoded: the algorithm lives in the function name itself
(`EVP_md5()`, `EVP_aes_256_gcm()`), or arrives as a string
(`EVP_get_cipherbyname("des-cbc")`) or an integer
(`RSA_generate_key(2048, ...)`, `DH_generate_parameters(512, ...)`). The C
collector interprets all four forms, covering OpenSSL's EVP and legacy APIs plus
libsodium, and a weak key size (RSA-1024, DH-512) flows into the same kx-layer
decommission routing as the config-level findings.

**Site overrides (no fork).** A site can extend or replace the built-in
detection rules without changing any code, via a directory of `.scm` files.
Resolution precedence: an explicit `--query-dir` (or `QRAMP_QUERY_DIR`), then a
project-local `.qramp/queries/` discovered upward from the working directory.
For each language the engine reads `<language>.extra.scm` (appended to the
built-in — the safe default, adds patterns without losing the defaults) and/or
`<language>.scm` (a full replacement, for total control). A site query can
classify its own matches entirely in the query file using `#set!` directives —
`(#set! "primitive" "symmetric-cipher") (#set! "algorithm" "des")` and optional
`key_length` / `mode` / `params` / `evidence` / `confidence` — so detecting an
internal crypto wrapper needs no interpreter code at all. A syntactically broken
site query never disables scanning: the engine falls back to the built-in and
records why. Each scan records the provenance of every `.scm` it merged
(builtin, extend, replace, or builtin-fallback) into the CBOM metadata.

```bash
# .qramp/queries/python.extra.scm teaches QRAMP an internal DES-equivalent wrapper:
qramp scan --source ./src --query-dir ./.qramp/queries -o cbom.json
```

### Key-exchange–layer weaknesses

Cryptographic weakness is not only about the primitive but about how it is
*used*. A static-RSA cipher suite (`TLS_RSA_WITH_...`, or an OpenSSL `kRSA` /
`AES256-SHA`-style cipher line) uses RSA as key **transport** — no forward
secrecy, Shor-broken. QRAMP models this as a distinct `key-agreement / rsa`
asset (separate from RSA keygen or RSA signatures), detects it in source
(cipher-suite constants) and config (`ssl_ciphers`), and resolves both into one
asset. Its rule-pack entry carries `remediate: {action: decommission}`, so the
planner routes it straight to a decommission recipe (a negotiated suite cannot
be "externalised" — the server must stop offering it), and the active
`decommission-legacy` probe then confirms the endpoint no longer negotiates it.

The same treatment covers **weak finite-field Diffie-Hellman**. Group strength
is the prime bit length: a ≤1024-bit group (or export-grade 512-bit) is
breakable *today* by Logjam-style precomputation, not merely by a future quantum
computer. QRAMP reads the actual bit length from `ssl_dhparam` PEM files (or the
filename when the file is absent), from SSH `KexAlgorithms` group tokens
(`diffie-hellman-group1-sha1` = 1024-bit, etc.), and from source-level
`dh.generate_parameters(key_size=…)`. A rule matching `algorithm: dh` with
`max_key_length: 1024` classifies these as needing decommissioning (route
straight to `decommission-legacy`), while a 2048-bit group keeps the standard
migration recipe (it is only quantum-broken, not classically weak). The active
probe adds capability-tiered export-DHE challenges: where the local TLS stack can
offer them, an endpoint that still negotiates an export-grade ephemeral-DH suite
fails the check; where it cannot, that specific probe is reported unprobeable
rather than passed.

### Certificate-chain weaknesses

A certificate can be cryptographically weak in ways that are independent of the
quantum question and actionable **today**. The cert collector flags three
dimensions, all fail-closed:

* **Weak subject key** — an RSA modulus below 2048 bits (`weak-key` tag).
* **Weak curve** — an EC key on a sub-224-bit curve such as secp192r1
  (`weak-curve` tag).
* **Weak signature** — a certificate signed with a forgeable digest (SHA-1 or
  MD5). The certificate's own signature algorithm is modelled as a *composite*
  signature asset keyed on the digest (`cert-sig:sha1`), so a SHA1-RSA cert is a
  distinct asset from a SHA256-RSA cert and can be classified on its own.

Validity is tracked too (`expiring-soon` within 90 days, `expired` past
notAfter). The rule pack routes weak certificates to a dedicated `reissue`
action — you cannot "externalise" or "decommission" a certificate, you replace
it — which the planner expands into a **reissue-certificate → deploy-and-revoke**
recipe. Each task carries a machine-checkable acceptance predicate: `qramp
verify` checks the operator-supplied refreshed scan of the same certificate file.
It validates supported hygiene requirements; deployment and revocation remain
manual, and a missing or unparseable replacement file is deferred. The `has_tag` rule-matcher
condition (added for this) lets policy select assets by the collector's tags
without hard-coding key sizes in code.

## Test

```bash
pytest -q          # see revision notes for the recorded environment and result
```

