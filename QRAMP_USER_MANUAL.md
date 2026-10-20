# QRAMP User Manual

**Version 0.1.1** · Cryptographic asset inventory and quantum-resistant migration planning

---

## Changes in 0.1.1

See [revision notes](REVISION_NOTES_zh.md) for fixes and
[reproducible experiments](examples/REVISION_EXPERIMENTS.md) for current results.
Tasks now represent owner/file or endpoint obligations. `verify` evaluates a
supplied refreshed scan and reports pass/fail/deferred/manual; it does not run a
rescan. Matching roots, queries and parsed target files are required for absence
checks. Missing/moved files and skipped collectors are deferred. C/Rust are
included. Investigation and certificate deployment/revocation remain manual.
The old asset-loss, 120-task and 20-pass examples do not apply to this version.

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Requirements](#2-system-requirements)
3. [Installation](#3-installation)
4. [Functional Modules](#4-functional-modules)
5. [Command Reference](#5-command-reference)
6. [Operation Guide](#6-operation-guide)
7. [CI Integration](#7-ci-integration)
8. [Validation and Accuracy](#8-validation-and-accuracy)
9. [Troubleshooting](#9-troubleshooting)
10. [Support and Version Information](#10-support-and-version-information)
11. [Appendix](#11-appendix)

---

## 1. Introduction

### 1.1 Overview

QRAMP answers a question most organisations cannot currently answer: *where is our cryptography, which of it will a quantum computer break, and how far along is the migration?*

It collects cryptographic evidence from source code, software bills of materials, package manifests, X.509 certificates, service configurations and live TLS endpoints; resolves that evidence into a CycloneDX **cryptographic bill of materials (CBOM)**; classifies and prioritises each asset with a versioned rule pack and an explicit Mosca-inequality urgency model; compiles a phased, dependency-ordered migration plan; and evaluates task acceptance against operator-supplied refreshed scan evidence.

Tasks carry explicit acceptance requirements. Supported checks use refreshed scan evidence; investigations, certificate deployment/revocation and unsupported profiles require operator evidence.

### 1.2 Key Features

- **Cross-language entity resolution** — the same algorithm seen in Python, Java and Go resolves to one asset with three occurrences.
- **Mosca-based prioritisation** — urgency from X+Y−Z (data secrecy lifetime + migration time vs. quantum arrival), not a hand-assigned severity.
- **Scoped acceptance** — `verify` checks refreshed scan evidence and records explicit status, timestamps and input hashes. Manual tasks remain manual.
- **Version-aware capability resolution** — `openssl@3.5` resolves to ML-KEM/ML-DSA; `openssl@3.0.13` does not. Unknown versions withhold gated capabilities rather than guessing.
- **Policy as versioned data** — the rule pack, provider map and alias map are YAML with dedicated linters, snapshot regression, and a `policy-diff` audit against real inventory.
- **Standards output** — CycloneDX 1.6 CBOM, SARIF 2.1.0, OpenVEX; all schema-validated and round-trip verified.
- **Provenance** — every rule cites the governing FIPS / NIST SP / RFC / CVE, and the citations flow through to SARIF help text and the report bundle.

### 1.3 Technical Architecture

Five layers, each a separate module boundary:

```
COLLECT   source-py · source-java · source-go · source-rust · source-c
          sbom · manifests · certs · configs · tls          (plugins, read-only)
   │
MODEL     CryptoAsset ← n × Occurrence  →  CBOM (CycloneDX 1.6)
   │      Component --provides--> CryptoAsset      (library → capability)
   │      Certificate --signed_by--> Certificate   (trust chain)
   │
ASSESS    versioned rule pack + Mosca X+Y−Z  →  P0–P3 tiers
   │
PLAN      task DAG under prereq / interop / window / capacity  →  schedule
   │
REPORT    CBOM · plan · dashboard · SARIF · VEX · graphs · bundle    ↺ verify
```

Implementation is roughly 10,000 lines of Python across 34 modules, with additional review regression tests in `tests/test_revision.py`.

### 1.4 Two Ways to Run an Audit

| | **CLI** | **Python API** |
|---|---|---|
| Entry point | `qramp <subcommand>` | `import qramp` |
| Best for | CI gates, one-off audits, reports | embedding, custom collectors, bulk analysis |
| Output | files + exit codes | `Inventory` objects |

Both drive the same engine. The CLI is a thin argument-parsing layer over the library.

---

## 2. System Requirements

### 2.1 Python Package

| Requirement | Value |
|---|---|
| Python | ≥ 3.10 (tested on 3.10, 3.11, 3.12) |
| OS | Linux, macOS, Windows |
| Compilation | none required |
| Core dependencies | `cryptography>=42`, `PyYAML>=6`, `networkx>=3` |

Optional extras:

| Extra | Adds | Effect if absent |
|---|---|---|
| `source` | tree-sitter + Python/Java/Go/Rust/C grammars | source collectors yield nothing and record why |
| `validate` | `cyclonedx-python-lib`, `jsonschema` | schema validation of exports is skipped |
| `versions` | `packaging` | falls back to a built-in PEP 440 comparator |
| `solver` | OR-Tools CP-SAT | falls back to deterministic list scheduling |
| `java` / `go` / `python` / `rust` / `c` | one grammar each | that language is not scanned |

Missing grammars skip their source collectors and are recorded. Such skipped collectors cannot supply successful absence-based acceptance evidence. The list fallback is deterministic; time-bounded CP-SAT can vary.

### 2.2 TLS Collection

The TLS collector and the active handshake probes need outbound TCP to the target host and an HMAC-signed scope file. They perform standard read-only handshakes only — no application data, no exploitation, no credential testing.

Active PQ-hybrid probing additionally needs a local OpenSSL that supports post-quantum groups (`X25519MLKEM768` and similar). Where it does not, the probe reports *unprobeable* with the specific reason rather than passing.

---

## 3. Installation

### 3.1 From Source

```bash
git clone https://github.com/Zhangtijerry/QRAMP.git qramp
cd qramp
pip install -e .
```

### 3.2 Recommended Install

```bash
pip install -e ".[source,validate,versions]"
```

This enables all five source collectors and schema validation. Add `solver` for the exact scheduler:

```bash
pip install -e ".[source,validate,versions,solver]"
```

### 3.3 Direct From GitHub

```bash
pip install "qramp[source,validate] @ git+https://github.com/Zhangtijerry/QRAMP.git"
```

### 3.4 Verify the Installation

```bash
qramp --help          # should list 30 subcommands
python -c "import qramp; print(qramp.__version__)"
```

```
0.1.0
```

Run the test suite:

```bash
pip install pytest
pytest -q
```

```
See REVISION_NOTES_zh.md for the current recorded test result.
```

The three skips are tests requiring `node` or `dot` on PATH; they are guarded and their absence is not an error.

---

## 4. Functional Modules

| Module | Role |
|---|---|
| `qramp.collectors` | evidence collection plugins (10 built-in) |
| `qramp.model` | `Inventory`, `CryptoAsset`, `Occurrence`, entity resolution, diff |
| `qramp.assess` | rule-pack evaluation, Mosca tiering |
| `qramp.plan` | task DAG construction and scheduling |
| `qramp.report` | dashboard, verify loop, CSV/issue export |
| `qramp.cyclonedx` | CycloneDX 1.6 CBOM import/export |
| `qramp.sarif` | SARIF 2.1.0 export |
| `qramp.vex` | VEX parsing, linting, suppression |
| `qramp.providermap` | version-aware library → capability resolution |
| `qramp.readiness` | migration readiness scoring, ROI-ranked upgrades |
| `qramp.simulate` | side-effect-free upgrade modelling |
| `qramp.handshake` | active TLS probes (capability-tiered) |
| `qramp.rulelint` | rule-pack static analysis |
| `qramp.policydiff` | policy change audit against real inventory |
| `qramp.timeline` | cross-scan progress tracking |
| `qramp.bundle` / `orgdash` / `prcomment` | deliverables |

### 4.1 Collectors

| Collector | Reads | Notes |
|---|---|---|
| `source-py` / `-java` / `-go` / `-rust` / `-c` | source trees | tree-sitter `.scm` queries; records `query_hash` |
| `sbom` | CycloneDX SBOM | maps components through the provider map |
| `manifests` | `package-lock.json`, `requirements.txt`, `go.mod`/`go.sum`, `pom.xml`, `Cargo.lock`/`Cargo.toml` | auto-discovery, no hand-written SBOM needed |
| `certs` | `.pem` / `.der` / `.crt` | weak key, weak curve, weak signature, validity, trust chain |
| `configs` | nginx, sshd, `java.security`, `ssl_dhparam` | cipher suites, KEX algorithms, DH group sizes |
| `tls` | live endpoints | read-only handshakes, HMAC-scoped |

### 4.2 The Rule Pack

Shipped pack: `transition-2024.3`, 35 rules, first-match-wins.

| Class | Rules | Meaning |
|---|---|---|
| `quantum_broken` | 18 | Shor-breakable, or classically weak today |
| `pq_ready` | 9 | standardised PQ (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, ASCON) |
| `quantum_weakened` | 7 | Grover-affected, or non-standardised PQ (FrodoKEM, BIKE, HQC, Classic McEliece) |
| `hybrid` | 1 | classical + PQ (X25519+ML-KEM-768, X-Wing) |

Remediation actions declared in the pack: `decommission` (3 rules), `reissue` (4 rules). Everything else routes to the default externalise/migrate recipe.

---

## 5. Command Reference

30 subcommands. Grouped by pipeline stage.

### 5.1 Core Pipeline

```
qramp scan    [--source DIR] [--sbom FILE] [--certs DIR] [--config DIR]
              [--manifests [DIR]] [--scope FILE] [--scope-key FILE]
              [--alias-map FILE] [--provider-map FILE] [--owners FILE]
              [--query-dir DIR] [-o OUT]

qramp assess  CBOM --rules FILE --lifetimes FILE [-o OUT]

qramp plan    ASSESSMENT --capacity FILE [--horizon 24m] [-o OUT]
              [--solver {auto,cpsat,list}] [--time-limit SECONDS]

qramp verify  PLAN --against CBOM [--phase N] [--evidence-out FILE]
              [--active-probe] [--scope FILE] [--scope-key FILE]
              [--attempts N]
```

`assess` requires both `--rules` and `--lifetimes`; `plan` requires `--capacity`. These are not optional.

`assess` and `plan` each write a **second file** alongside the named output: `<out>.summary.json` and `<out>.json` respectively.

### 5.2 Analysis

```
qramp readiness  CBOM [--map FILE] [--json] [--min-readiness PCT]
                 [--max-unaddressable N]
qramp simulate   CBOM --upgrade NAME=VERSION [--upgrade ...] [--map FILE] [--json]
qramp impact     CBOM [--component NAME] [--algorithm NAME] [--list]
qramp chain      CBOM [--leaf SUBSTRING] [--weak-only]
qramp diff       OLD NEW [--detailed]
qramp timeline   CBOM [CBOM ...] [--series P0,P1] [--svg FILE] [--html FILE]
                 [--json] [--min-improvement N] [--label LABEL]
qramp resolve-provider COMPONENT VERSION [--map FILE]
```

`--upgrade` is repeatable. `timeline` accepts a directory of CBOMs.

### 5.3 Policy Tooling

```
qramp lint-rules         RULES [--snapshot FILE] [--update-snapshot] [--strict]
qramp lint-provider-map  [MAP] [--snapshot FILE] [--strict]
qramp lint-vex           VEX [--cbom FILE] [--strict]
qramp lint-aliases       [ALIASES] [--map FILE] [--snapshot FILE]
                         [--update-snapshot] [--cbom FILE] [--max-wrapper-pct N] [--strict]
qramp provenance         [RULES] [--format {text,markdown,json}] [--cbom FILE]
                         [--require-references]
qramp policy-diff        CBOM --kind {rules,provider-map,vex} --old FILE --new FILE
                         [--lifetimes FILE] [--json] [--fail-on-worse]
qramp baseline           ASSESSMENT -o OUT [--exposure CLASSES]
qramp baseline-check     ASSESSMENT --baseline FILE [--exposure CLASSES] [--strict]
```

`lint-provider-map`, `lint-aliases` and `provenance` default to the built-in files when no path is given.

### 5.4 Output

```
qramp report        CBOM [-o OUT] [--map FILE] [--vex FILE] [--history CBOM ...]
qramp bundle        CBOM [-o DIR] [--rules FILE] [--vex FILE] [--history CBOM ...]
                    [--map FILE] [--title TEXT]
qramp export        PLAN --format {issues,csv,cyclonedx,sarif,vex} -o OUT
                    [--rules FILE] [--min-level {error,warning,note}]
                    [--include-ok] [--vex FILE] [--vex-format {openvex,cyclonedx}]
qramp graph         CBOM [--which {dependency,chain}] [--format {dot,mermaid}] [-o OUT]
qramp pr-comment    CBOM [--base CBOM] [--gates JSON] [--history CBOM ...]
                    [--title TEXT] [--subtitle TEXT] [--compact]
                    [--report-url URL] [--map FILE] [-o OUT]
qramp repo-card     ASSESSMENT -o OUT --name NAME [--map FILE] [--gates FILE] [--url URL]
qramp org-dashboard CARDS [CARDS ...] -o OUT [--title TEXT]
qramp import        CBOM -o OUT [--tool NAME] [--merge FILE]
qramp sign-scope    SCOPE --key FILE
```

### 5.5 Exit Codes

Verified empirically:

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `verify` | all predicates passed | — | **one or more tasks failed** |
| `readiness --min-readiness` | at or above threshold | below threshold | — |
| `baseline-check` | no new exposed assets | new asset found | — |
| `lint-*` | clean | errors found | — |
| `provenance --require-references` | every rule cites a standard | a rule lacks references | — |
| `policy-diff --fail-on-worse` | no regression | posture worsened | — |
| `scan` / `assess` / `plan` | completed | uncaught error | — |

`verify` returning 2 on the shipped testbed is **expected** — see §9.3.

### 5.6 Python API

```python
from qramp import Inventory, scan, assess, plan

inv = Inventory()
scan(inv,
     source_dir="./src",
     cert_dir="./certs",
     config_dir="./etc",
     manifests_dir=".",
     owner_map=owners)
inv.save("cbom.json")

summary = assess.run("cbom.json", rules="rules.yaml",
                     lifetimes="lifetimes.yaml", out="assessment.json")
```

`scan()` recognises: `source_dir`, `sbom_path`, `manifests_dir`, `cert_dir`, `config_dir`, `scope_path` + `scope_key`, plus `owner_map`, `provider_map`, `alias_map`, `query_dir`.

Also exported at package level: `CryptoAsset`, `Occurrence`, `diff`.

---

## 6. Operation Guide

### 6.1 First Run — the Shipped Testbed

The repository ships a deliberately vulnerable `testbed/`: hard-coded MD5/DES literals across five languages, an RSA-1024 certificate, a SHA-1 root CA signing a strong leaf, a secp192r1 certificate, 512/1024-bit DH groups, and static-RSA cipher suites.

```bash
qramp sign-scope testbed/testbed.scope.yaml --key testbed/scope.key

qramp scan --source testbed/sample-app \
           --sbom   testbed/sample-app/sbom.cdx.json \
           --certs  testbed/certs \
           --config testbed/etc \
           --owners testbed/policy/owners.yaml \
           -o cbom.json
```

```
# Collector output includes scan roots, scanned files, query hashes and errors.
```

Add `--manifests testbed/manifests` for the complete revision evaluation. With all
source grammars installed that configuration records 52 algorithm assets and
125 occurrences; internal reloading retains all 52 assets. Missing grammars are
recorded and cannot supply successful acceptance evidence.

### 6.2 Classify and Prioritise

```bash
qramp assess cbom.json \
      --rules src/qramp/rules/transition-2024.yaml \
      --lifetimes testbed/policy/data-lifetimes.yaml \
      -o assessment.json
```

```
[assess] rule pack transition-2024.3 (5613092fb16894de)
         classes: quantum_broken=36  unknown=7  quantum_weakened=6  pq_ready=3
         tiers:   P2=37  P1=6  P3=6  OK=3
```

The hash after the pack version identifies the exact policy that produced this classification.

`unknown` means no rule matched. On your own codebase this number is worth watching — it is uncovered surface, not clean surface.

### 6.3 Plan

```bash
qramp plan assessment.json --capacity testbed/policy/teams.yaml \
      --horizon 24m -o plan.yaml
```

```
# Run scripts/reproduce_revision.py for current per-location task counts and schedules.
```

With OR-Tools installed, compare the two schedulers:

```bash
qramp plan assessment.json --capacity teams.yaml --horizon 30m --solver cpsat --time-limit 8
qramp plan assessment.json --capacity teams.yaml --horizon 30m --solver list
```

Both report `feasible_within_horizon`, `makespan_months` and `over_horizon_tasks`, so an under-capacity plan surfaces rather than silently overflowing.

### 6.4 Verify

```bash
qramp verify plan.yaml --against cbom.json --phase 1 --evidence-out evidence.json
```

```
# Inspect status_counts: pass, fail, deferred and manual. Non-passes exit 2.
```

This evaluates the CBOM supplied to `--against`; run collectors separately after changes. Absence checks pass only with matching scope and complete target evidence. Unsupported checks and manual obligations remain explicit non-passes.

Acceptance predicates by task type:

See the complete current acceptance table in [README](README.md#task-acceptance-against-refreshed-evidence).
Each task covers its recorded owner/file or endpoint. New uses elsewhere require
a fresh assessment and baseline/drift review; passing one target is not a global
clean-inventory verdict.

### 6.5 Readiness and Upgrade Simulation

```bash
qramp readiness assessment.json
```

```
[readiness] 0.0% of PQC-migration assets are already migratable (0/27)
  migration-blocked: 27 (27 addressable by a library upgrade)
  ROI-ranked upgrade recommendations:
   1. openssl 3.0.13 -> 3.5
      unlocks ml-dsa, ml-kem → unblocks 27 asset(s) (P1×3, P2×21, P3×3)   [ROI 16.29]
```

*Migration-blocked* means a quantum-broken key-agreement or signature asset has no deployed library providing the quantum-safe replacement. The fix is a library upgrade, not a code change alone.

```bash
qramp simulate assessment.json --upgrade openssl=3.5
```

```
[simulate] upgrading openssl (3.0.13 -> 3.5)
  + openssl gains: ml-dsa, ml-kem
  migration readiness: 0.0% → 100.0%
  migration-blocked assets: 27 → 0  (unblocks 27)
```

Note the wording: **unblocked**, never *resolved*. The library becomes available; the code still has to switch. The simulation is side-effect free and validates the request — a downgrade or an undeployed component is flagged rather than silently ignored.

### 6.6 Certificate Trust Chains

```bash
qramp chain assessment.json --weak-only
```

```
⚠ CN=secure.example.com: strong leaf, but chain broken by CN=SHA1 Legacy Root CA
      leaf CN=secure.example.com [leaf]
      CA   CN=SHA1 Legacy Root CA [CA]  ← weak-signature
```

The headline case: a 2048-bit, SHA-256 leaf looks clean in isolation, but a SHA-1 CA above it makes the whole chain forgeable. Per-certificate analysis cannot see this.

### 6.7 Dependency Impact

```bash
qramp impact assessment.json --list
qramp impact assessment.json --component openssl
qramp impact assessment.json --algorithm rsa
```

`--component` splits provided assets into **uniquely provided** (a genuine capability loss) and **still available** (another library also ships them). Removing OpenSSL from the testbed uniquely loses AES-256 and ECDH, but RSA survives via `cryptography` — so an RSA migration cannot be completed by dropping one library.

### 6.8 Your Own Project

```bash
cd /path/to/project

qramp scan --source . --manifests -o cbom.json
qramp assess cbom.json --rules /path/to/qramp/src/qramp/rules/transition-2024.yaml \
      --lifetimes lifetimes.yaml -o assessment.json
qramp readiness assessment.json
qramp bundle assessment.json -o report --rules /path/to/rules.yaml --title "Acme PQC"
```

`--manifests` walks the tree for lock files and feeds crypto-relevant dependencies through the version-aware provider map — no hand-written SBOM required. Vendored trees (`node_modules`, `vendor`, `target`) are skipped.

Wrapper packages whose version does not track the underlying library (`pyOpenSSL`, `openssl-sys`) are resolved **fail-closed**: their version does not drive version gates, and they are marked `~wrapper`. This keeps PQC attribution honest at the cost of being conservative.

Review collector coverage when interpreting zero findings. Nonexistent scan directories are rejected in 0.1.1.

---

## 7. CI Integration

### 7.1 Ready-Made Workflows

| File | Purpose |
|---|---|
| `examples/ci-full-pipeline.yml` | three-job pipeline: `policy-lint`, `crypto-scan`, `policy-audit` |
| `examples/github-code-scanning.yml` | minimal: scan + upload SARIF |
| `examples/org-dashboard.yml` | scheduled multi-repo roll-up |
| `.github/workflows/ci.yml` | the project's own test matrix |

These live under `examples/` and are **not** executed by GitHub. Copy the one you want into `.github/workflows/`.

### 7.2 Enabling a Gate Mid-Migration

A hard gate on a codebase that already contains quantum-broken crypto is red on day one and can never be switched on. Freeze the backlog first:

```bash
qramp baseline assessment.json -o .qramp/baseline.json
qramp baseline-check assessment.json --baseline .qramp/baseline.json
```

`baseline-check` fails only on a **new** exposed asset. It reports three counts: `new` (blocks), `accepted` (baselined), `resolved` (backlog shrank). Regenerate the baseline smaller as migration progresses; `--strict` fails when stale entries remain, forcing the ratchet.

### 7.3 VEX Exceptions

A baseline says "not migrated yet". VEX says "assessed and accepted for a stated reason" — a non-security cache key, an unreachable path, a compensating control.

```bash
qramp lint-vex vex.yaml --cbom assessment.json
qramp export assessment.json --format sarif --vex vex.yaml -o q.sarif
```

Applied to SARIF, accepted findings get a native `suppressions[]` entry, so GitHub shows them dismissed rather than re-alerting. On the testbed this drops active error findings from 57 to 50.

### 7.4 Policy Change Audit

```bash
qramp policy-diff assessment.json --kind rules \
  --old rules.yaml --new rules.next.yaml --lifetimes lifetimes.yaml --fail-on-worse
```

Where the linters ask "is the new policy internally consistent?", `policy-diff` asks "what does it do to the assets we actually have?" It catches, for example, lowering OpenSSL's PQC gate from `>=3.5` to `>=3.0` — which would claim the deployed 3.0.13 provides ML-KEM and unblock assets it cannot protect.

---

## 8. Validation and Accuracy

### 8.1 Test Suite

The review regression suite and the original suite were run on Linux with
Python 3.12; recorded results and dependency versions are in the revision notes
and experiment outputs. The CI matrix defines additional platform checks; those
are not claimed as locally executed validation for this revision.

### 8.2 Standards Conformance

- **CycloneDX 1.6** — exports validate against the official JSON schema and are round-trip verified: `cyclonedx-python-lib` parses the output into its object model and re-serialises it. QRAMP-specific enrichment lives in a `qramp:` property namespace, so schema validity holds. Imported-tool provenance differs from native collector coverage and cannot substitute for a fresh native acceptance scan.
- **SARIF 2.1.0** — validated against the official schema. Results carry a partial fingerprint keyed on asset identity and file but deliberately **not** line number, so GitHub tracks a finding across commits when edits shift lines.
- **OpenVEX / CycloneDX VEX** — the OpenVEX justification vocabulary maps onto CycloneDX `analysis.justification`.

### 8.3 Scheduler Comparison

Run `python scripts/reproduce_revision.py --sensitivity` for seven controlled
capacity/duration/size configurations and all raw schedules. E measures weighted
start delay. CP-SAT uses one worker, seed 42 and a 10-second budget by default;
inspect status/bounds and do not assume optimality or superiority.

### 8.4 Fail-Closed Behaviour

Verified deliberate fail-closed paths:

- Unknown or unparseable component versions **withhold** version-gated capabilities.
- `increase-parameters` fails when a key length is unknown.
- Wrapper packages cannot drive version gates.
- Active probes that cannot be performed report *deferred* with a reason, never a pass.
- A syntactically broken site `.scm` query falls back to the built-in and records why.

### 8.5 Scope and Limitations

- QRAMP finds cryptography that appears in code, manifests, certificates, configuration or on the wire. It cannot see crypto inside opaque binaries, HSMs, or third-party services — for those, register a custom collector.
- Classification is only as good as the rule pack. `unknown` assets are uncovered surface.
- The Mosca model needs a `Z` estimate (quantum arrival). That is an assumption, not a measurement.
- The provider map covers common libraries; a site-specific library needs a map entry before its capabilities resolve.
- Nonexistent scan directories are rejected. Missing grammar, parse errors and absent target files prevent absence-based acceptance.

---

## 9. Troubleshooting

### 9.1 The Scan Reports Zero Assets

Nonexistent source/certificate/configuration/manifest directories are rejected
with a nonzero exit. An existing directory can still contain no supported files,
or an optional grammar can be missing. Inspect collector stats, including roots,
scanned_paths, errors, query hashes and skipped reasons. Zero detections are not
proof that all cryptography in an environment has been found.

### 9.2 Source Collectors Report Zero Call Sites

The tree-sitter grammars are not installed. The scan output names the missing module:

```
{'name': 'source-py', 'files': 0, 'call_sites': 0,
 'skipped': "tree-sitter grammar 'tree_sitter_python' not installed"}
```

```bash
pip install -e ".[source]"
```

The scan is still valid without them — SBOM, manifest, certificate and config collection are unaffected — but source-level findings will be missing entirely.

### 9.3 `verify` Exits 2 and Fails My Build

That is correct behaviour when tasks have not been remediated. Exit 2 means "one or more selected tasks are failed, deferred, or manual", which on the shipped testbed is the intended outcome — the planted MD5/DES literals and weak certificates are deliberately unfixed.

In CI, assert the expected code rather than masking it with `|| true`:

```bash
set +e; qramp verify plan.yaml --against cbom.json --phase 1; code=$?; set -e
[ "$code" -eq 2 ] || { echo "expected 2, got $code"; exit 1; }
```

A `0` here on the unremediated testbed would mean the predicates stopped detecting the planted weaknesses — that is the regression worth catching.

### 9.4 `rules/transition-2024.yaml` Not Found

Several README examples use a shortened path. The actual location in a source checkout is:

```
src/qramp/rules/transition-2024.yaml
```

Commands that default to the built-in pack (`lint-provider-map`, `lint-aliases`, `provenance`) do not need a path at all.

### 9.5 `UnicodeDecodeError: 'charmap' codec can't decode byte 0x9d` on Windows

Fixed in the current tests, but the mechanism is worth knowing. Python's default text encoding follows the system locale — UTF-8 on Linux/macOS, **cp1252 on Windows**. Reading a UTF-8 file with `Path.read_text()` and no explicit encoding therefore fails on Windows when the content contains a byte undefined in cp1252.

`❌` (U+274C) encodes as `e2 9d 8c`; **0x9D is undefined in cp1252** and raises immediately. Other emoji (🔴 🟢 🟠 ✅ ➖) decode to mojibake rather than raising, which is why only the two tests touching a *failure* gate status broke.

Always pass `encoding="utf-8"` explicitly. Do not paper over it with `PYTHONUTF8=1` — that hides the next occurrence.

### 9.6 `assess` Rejects My Command Line

`--rules` and `--lifetimes` are both required; `plan` requires `--capacity`. There are no defaults. A minimal lifetimes file:

```yaml
default_years: 3
tags:
  - {tag: external, years: 7}
```

### 9.7 Many Assets Classified `unknown`

No rule matched them. This is uncovered surface, not clean surface. Options:

- `qramp lint-rules <pack>` to check the pack for unreachable rules that may be shadowing intended matches.
- Add rules to the pack (it is data, not code).
- Add site-specific detection in `.qramp/queries/<language>.extra.scm` — a site query can classify its own matches with `#set!` directives, no interpreter code required.

### 9.8 Readiness Is 0% and Everything Is Blocked

Expected when no deployed library provides ML-KEM or ML-DSA. Run `qramp simulate` to confirm which upgrade clears it before touching a manifest. If a PQC library is already deployed and readiness is still low, check whether it resolves through a wrapper:

```bash
qramp lint-aliases --cbom assessment.json --max-wrapper-pct 40
```

A high wrapper share means version-gated capabilities are being withheld and the assessment is conservative.

### 9.9 Active Probe Reports "unprobeable"

The local TLS stack cannot offer the required parameters — PQ hybrid groups unsupported by the local OpenSSL, or legacy suites compiled out. This is deliberate: the probe fails closed with a specific reason rather than reporting a pass it cannot substantiate. Run from a host whose OpenSSL supports the groups in question.

### 9.10 Certificate Count Looks Low

Inspect collector `files`, `certificates` and `errors`. In 0.1.1 each candidate
certificate file is counted and an unparseable candidate is recorded as an error.
Such errors defer absence-based acceptance. PEM bundles can contain several
certificates, so candidate-file and certificate totals need not be equal.

---

## 10. Support and Version Information

### 10.1 Repository

`https://github.com/Zhangtijerry/QRAMP`

### 10.2 Version

| Component | Version |
|---|---|
| Package | 0.1.1 |
| Rule pack | transition-2024.3 |
| Provider map | provider-map-0.2 |
| CycloneDX target | 1.6 |
| SARIF target | 2.1.0 |

Version is declared in `pyproject.toml`, `CITATION.cff` and `qramp.__version__`. Keep the three aligned when releasing.

### 10.3 Author

Ti Zhang (张媞) — 21111104@bjtu.edu.cn — [ORCID 0009-0005-6137-4350](https://orcid.org/0009-0005-6137-4350)

Beijing Key Laboratory of Security and Privacy in Intelligent Transportation,
Beijing Jiaotong University, Beijing 100044, China

### 10.4 Licence

MIT. Copyright (c) 2026 Ti Zhang.

### 10.5 Citation

`CITATION.cff` is in the repository root; GitHub's "Cite this repository" button renders it in APA and BibTeX.

```bibtex
@software{zhang_qramp_2026,
  author  = {Zhang, Ti},
  title   = {{QRAMP}: cryptographic asset inventory and quantum-resistant migration planning},
  year    = {2026},
  version = {0.1.1},
  license = {MIT},
  url     = {https://github.com/Zhangtijerry/QRAMP}
}
```

### 10.6 Testing

```bash
pip install -e ".[source,validate,versions]" pytest
pytest -q
```

To reproduce the Windows encoding class of bug on Linux:

```bash
PYTHONUTF8=0 PYTHONCOERCECLOCALE=0 LC_ALL=C LANG=C pytest -q
```

---

## 11. Appendix

### A. Complete Command List

**Pipeline** — `scan`, `assess`, `plan`, `verify`
**Analysis** — `readiness`, `simulate`, `impact`, `chain`, `diff`, `timeline`, `resolve-provider`
**Policy** — `lint-rules`, `lint-provider-map`, `lint-vex`, `lint-aliases`, `provenance`, `policy-diff`, `baseline`, `baseline-check`
**Output** — `report`, `bundle`, `export`, `graph`, `pr-comment`, `repo-card`, `org-dashboard`
**Interop** — `import`, `sign-scope`

### B. Glossary

| Term | Meaning |
|---|---|
| **CBOM** | Cryptographic Bill of Materials — the CycloneDX inventory of cryptographic assets |
| **Occurrence** | one observation of an asset at a locator (`path:line`, `host:port`, cert file) |
| **Asset** | a resolved cryptographic capability; one asset may have many occurrences across languages |
| **Exposure class** | `quantum_broken`, `quantum_weakened`, `pq_ready`, `hybrid`, `unknown` |
| **Tier** | P0–P3 urgency from the Mosca inequality; `OK` when no migration is needed |
| **Mosca X+Y−Z** | data secrecy lifetime + migration duration vs. quantum arrival estimate |
| **Migration-blocked** | a quantum-broken KEX/signature asset with no deployed PQC replacement available |
| **Readiness** | share of PQC-migration assets that already have a deployable replacement |
| **Wrapper** | a binding package whose version does not track the underlying library; fail-closed |
| **Baseline** | frozen pre-existing exposure, accepted so a gate blocks only new regressions |
| **VEX** | Vulnerability Exploitability eXchange — recorded, justified exceptions |
| **Provenance** | the governing standard (FIPS / NIST SP / RFC / CVE) each rule cites |
| **query_hash** | content hash of the `.scm` detection query that produced a finding |

### C. Repository Layout

```
src/qramp/
  __init__.py          scan() entry point, public API re-exports
  model.py             Inventory, CryptoAsset, Occurrence, entity resolution
  assess.py            rule evaluation, Mosca tiering
  plan.py              task DAG, CP-SAT and list schedulers
  report.py            dashboard, verify loop, CSV/issues
  cyclonedx.py         CBOM import/export
  sarif.py  vex.py     code-scanning and exception outputs
  providermap.py       version-aware capability resolution
  readiness.py  simulate.py
  handshake.py         active TLS probes
  rulelint.py  policydiff.py  aliasmap.py  baseline.py
  timeline.py  bundle.py  orgdash.py  prcomment.py
  svggraph.py  graphexport.py
  cli.py               argument parsing for 30 subcommands
  collectors/          10 collectors + tsquery.py
    queries/*.scm      tree-sitter detection queries (versioned data)
  rules/               transition-2024.yaml
  data/                provider-map.yaml, manifest-aliases.yaml

testbed/               deliberately vulnerable fixtures
examples/              CI workflow templates
tests/test_qramp.py    377 tests
```

### D. Extending

**New collector** — register under the `qramp.collectors` entry point. No fork needed.

**New detection pattern** — add a `.scm` query. Resolution precedence: `--query-dir` or `QRAMP_QUERY_DIR`, then a project-local `.qramp/queries/` discovered upward. For each language the engine reads `<language>.extra.scm` (appended to the built-in) and/or `<language>.scm` (full replacement). A site query can classify its own matches with `#set!` directives:

```scheme
(#set! "primitive" "symmetric-cipher") (#set! "algorithm" "des")
```

Optional: `key_length`, `mode`, `params`, `evidence`, `confidence`.

**New policy** — the rule pack, provider map and alias map are versioned YAML with matching linters and snapshot regression. Edit the data, run the linter, commit the snapshot.

### E. Remaining limitations and historical defects

| ID | Severity | Description | Workaround |
|---|---|---|---|
| §9.1 | Fixed | Nonexistent scan directories are rejected in 0.1.1 | use valid paths |
| §9.10 | Fixed | Certificate parse failures are counted and recorded in errors | replace invalid inputs before acceptance |
| — | Low | Manifest parse failures not recorded in stats | inspect `dependencies_seen` against expectation |
| — | Low | `assess.py:109`, `plan.py:334` write text without explicit encoding | safe today (`json.dump` emits ASCII) |
| — | Fixed | Build/cache exclusions supplied in `.gitignore` | — |
