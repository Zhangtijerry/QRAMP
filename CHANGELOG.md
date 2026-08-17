# Changelog

All notable changes to QRAMP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-17

### Added

- **Collectors**: source-py, source-java, source-go, source-rust, source-c
  (tree-sitter query-driven), sbom, manifests, certs, configs, tls.
- **Cross-language entity resolution**: the same algorithm seen across
  languages resolves to one asset with multiple occurrences.
- **Assessment engine**: versioned YAML rule pack (`transition-2024.3`) with
  Mosca X+Y−Z urgency model, classifying assets into P0–P3 tiers.
- **Migration planner**: task DAG with prerequisite ordering, per-owner
  capacity constraints, and two interchangeable schedulers (CP-SAT exact
  solver and deterministic list-scheduling heuristic).
- **Verification loop**: machine-checked acceptance predicates for every task
  type (`externalise-algorithm`, `enable-hybrid-kex`, `decommission-legacy`,
  `increase-parameters`), with evidence bundles.
- **Active handshake probes**: capability-tiered TLS probes for PQ hybrid
  key exchange and legacy decommissioning, gated by signed scope files.
- **Standards-compliant exports**: CycloneDX 1.6 CBOM, SARIF 2.1.0,
  OpenVEX, CycloneDX VEX — all schema-validated.
- **Dependency graph**: version-aware provider map linking libraries to
  cryptographic capabilities, with manifest auto-discovery.
- **Certificate trust-chain analysis**: weakest-link detection across
  issuer chains.
- **Migration readiness scoring**: ROI-ranked library upgrade
  recommendations and side-effect-free upgrade simulation.
- **Reporting**: interactive HTML dashboard, timeline trend charts,
  shareable report bundles, org-level dashboard, PR comment summaries.
- **Policy tooling**: `lint-rules`, `lint-provider-map`, `lint-aliases`,
  `lint-vex`, snapshot regression, `policy-diff` against real inventory.
- **CI integration**: baseline ratcheting, SARIF upload, gate summary,
  full pipeline example for GitHub Actions.
- **Provenance**: every rule cites its governing FIPS / NIST SP / RFC / CVE
  standard; citations flow through to all outputs.

[0.1.0]: https://github.com/Zhangtijerry/QRAMP/releases/tag/v0.1.0
