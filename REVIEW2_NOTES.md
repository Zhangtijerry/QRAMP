# QRAMP 0.1.2 validation notes

Version 0.1.2 builds on commit 813aa7b. The archived v0.1.1 baseline has DOI 10.5281/zenodo.23487117. The scheduling and external validation outputs are retained from the review runs. Version 0.1.2 updates the package and export version metadata and documentation without changing the evaluated scheduling or detection logic.

## Implemented changes

- Task IDs hash the canonical asset tuple, owner, collector and root-relative
  location. Dependency locator fragments are retained; TLS endpoints retain
  their endpoint identity. Task and solver-model order is sorted by ID.
- Absolute evidence paths and root/query matching remain unchanged. A moved
  checkout needs fresh scans/plans; identity invariance is not authorisation to
  accept evidence from a different root. Rootless absolute legacy locators are
  rejected for planning with a rescan message. Relative subdirectories distinguish
  same-named files. SBOM and manifest collector metadata now record roots.
- Verification explicitly outputs `migration_status: not_established`, the narrow
  `acceptance_scope`, added observed identities and reassessment requirements;
  the CLI prints the same limitation. Existing Boolean and exit-code semantics
  are retained. Alias resolution and a policy gate for all new identities are
  **not** claimed to be fixed. The two requested acceptance counterexamples are
  preserved, measured and covered by regression tests.

## Validation

```
python -m pip install -r requirements-review2.txt
python -m pip install -e ".[source,solver,validate,versions,dev]"
python -m pytest -q -rs
python scripts/reproduce_revision.py --out revision2-results --sensitivity --repeats 3 --time-limit 10
python scripts/validate_review2.py --out review2-validation
```

OpenSSL CLI is required for external certificate/TLS reference comparisons.
The validation command makes **only signed loopback TLS connections** and uses
included input snapshots. It does not download external projects. External
project provenance, immutable commits, file hashes and licences are in
`testbed/external-validation`. Derived SBOM regeneration additionally uses
cyclonedx-bom 8.0.1; see the provenance file. They are representations of the same
two manifests, not extra independent deployment inventories.

- Tests: 418 passed; 3 optional Playwright tests skipped; 12.01 s on Linux/Python
  3.12.14. The earlier published cross-platform CI results are baseline-only.
- Source: 15 inspected hash/MAC construction sites in three complete external
  Python files, TP=7, FP=0, FN=8. Precision 100%, recall 46.7%. Six missed sites
  invoke selectable digests, two construct HMACs. Purposive file sample, not a
  representative project inventory or independent/blinded human annotation.
- Certificates: 143 certifi entries; all compared serial/key/curve/signature fields
  match OpenSSL 3.5.7. Weak signature digest TP=18, FP=0, FN=0, TN=125. This is not
  trust-path validation or a claim that a self-signed SHA-1 root is exploitable.
- Configs: OpenJDK comment/continuation parsing causes 3 false positives among
  five selected prohibited-category entries; two true negatives. The supported
  nginx/OpenSSH directive families have no active declaration in the two
  templates, providing negative controls only. JDK MD5withRSA is not a generic
  prohibition of every MD5 use. Inherited settings and daemon defaults are not
  evaluated. These observed parser limitations were not tuned away.
- Manifests: one of two declared cryptography providers recovered; the unpinned
  Ansible declaration is omitted. Two independently generated CycloneDX
  representations both recover that declared component. Capability-edge
  correctness and runtime usage are not independently measured.
- TLS: two local profiles x four forced versions; TP=3, FP=0, FN=1, TN=4. TLS 1.2
  available only with a static-RSA suite is missed by the collector client.
  No Internet endpoint or successful PQ handshake was evaluated.
- Scheduling: 28 schedules, seven configurations; all passed separately
  implemented precedence/concurrency checks. CP-SAT: all 21 runs FEASIBLE.
  New baseline E=2,211,900 (CP-SAT), 2,264,880 (list), reduction 2.34%; both finish
  month 45. Across configurations reduction is 2.3–34.3%, objective gaps
  89.4–98.2%, not evidence of optimality. All raw schedules are included.
- Relocation: three directory prefixes including spaces and nesting; all 179 IDs,
  prerequisite lists, list starts and CP-SAT model fingerprints identical. Under
  a separate 0.5 deterministic-work budget and 60 s cap, all three CP-SAT schedules
  were also identical. The reported scheduling tables use 10 s wall-clock limits;
  other machines may return different feasible incumbents.

The existing source fixtures and collector queries are unchanged. The repeated
sensitivity runs used the final scheduling implementation; only the version
string and documentation were updated afterwards. `summary.json` records this
provenance. All numeric claims refer to included local runs, not fresh remote CI.

## Before submission

Review the source reference labels and newly measured limitations with the
coauthors. If the reviewer requires validation by people independent of the
authors, that still needs to be arranged; externally sourced files and separate
reference tools do not establish independent human annotation.
