# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.aliasmap — load and lint the manifest package-name alias map.

The manifest collector normalises ecosystem package names (pyOpenSSL, the Maven
`bcprov-jdk18on` artifact, the native `libssl`) to the provider-map component key
for the underlying library. That mapping used to live in code; it is now
versioned YAML data (`data/manifest-aliases.yaml`), so a team can extend it for
their own ecosystems the same way they extend the rule pack or the provider map.

Like the other policy inputs, the alias map carries a version and has a linter
(`qramp lint-aliases`) that catches the editing mistakes the format invites:
missing fields, duplicate package entries, a wrapper flag that is not a boolean,
and — with a provider map to check against — aliases that point at a component
key the provider map does not define (a mapping that can never resolve to any
capability).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import yaml

DEFAULT_ALIASES = os.path.join(os.path.dirname(__file__), "data",
                               "manifest-aliases.yaml")


def load(path: str | None = None) -> dict:
    """Load the alias map and return a normalised lookup:
    {package_lower: (component_key, tracks_version)}."""
    doc = yaml.safe_load(open(path or DEFAULT_ALIASES, encoding="utf-8"))
    return build_lookup(doc)


def build_lookup(doc: dict) -> dict:
    """Turn a parsed alias document into a {package: (component, tracks)} map."""
    out = {}
    for a in doc.get("aliases", []):
        pkg = (a.get("package") or "").strip().lower()
        if not pkg:
            continue
        comp = a.get("component") or pkg
        tracks = a.get("tracks_version", True)
        out[pkg] = (comp, bool(tracks))
    return out


@dataclass
class Finding:
    level: str
    package: str
    message: str


def lint(doc: dict, provider_map: dict | None = None) -> list[Finding]:
    """Static-check an alias map. If `provider_map` is given, also verify every
    alias target is a component the provider map actually defines."""
    findings: list[Finding] = []
    aliases = doc.get("aliases", [])
    if not aliases:
        findings.append(Finding("warning", "-", "alias map has no aliases"))
    known_components = None
    if provider_map is not None:
        known_components = {e.get("component", "").lower()
                            for e in provider_map.get("components", [])}

    seen: dict[str, int] = {}
    for i, a in enumerate(aliases):
        pkg = a.get("package")
        pid = pkg or f"<alias #{i}>"
        if not pkg:
            findings.append(Finding("error", pid, "alias entry is missing 'package'"))
            continue
        key = pkg.strip().lower()
        if key in seen:
            findings.append(Finding("error", pid,
                f"duplicate package (first at position {seen[key]}); "
                f"an alias should map a package exactly once"))
        seen.setdefault(key, i)

        comp = a.get("component")
        if not comp:
            findings.append(Finding("error", pid, "alias is missing 'component'"))
        elif known_components is not None and comp.lower() not in known_components:
            findings.append(Finding("warning", pid,
                f"component {comp!r} is not defined in the provider map, so this "
                f"alias can never resolve to a capability"))

        tracks = a.get("tracks_version", True)
        if not isinstance(tracks, bool):
            findings.append(Finding("error", pid,
                f"'tracks_version' must be true or false, got {tracks!r}"))

        # a self-alias that only lowercases is harmless but worth noting
        if comp and pkg.strip().lower() == comp.strip().lower() and \
                a.get("tracks_version", True) is True and "ecosystem" not in a:
            findings.append(Finding("info", pid,
                "alias maps a package to itself with no ecosystem note; "
                "this is a no-op unless the provider map keys differ in case"))

    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.level])
    return findings


def resolve_snapshot(doc: dict) -> dict:
    """Freeze the alias resolution as a stable {package: {component,
    tracks_version}} map. Used to detect accidental edits that change a known
    package-name mapping (e.g. a typo that stops pyOpenSSL resolving to openssl,
    or a wrapper flipped to track its own version and wrongly claiming ML-KEM)."""
    lut = build_lookup(doc)
    return {pkg: {"component": comp, "tracks_version": tracks}
            for pkg, (comp, tracks) in sorted(lut.items())}


def diff_snapshot(baseline: dict, current: dict) -> dict:
    """Compare a frozen baseline against the current resolution. Returns the
    packages whose mapping changed, and those added or removed."""
    changed = []
    for pkg in sorted(set(baseline) & set(current)):
        if baseline[pkg] != current[pkg]:
            changed.append({"package": pkg, "baseline": baseline[pkg],
                            "current": current[pkg]})
    only_baseline = sorted(set(baseline) - set(current))
    only_current = sorted(set(current) - set(baseline))
    return {"changed": changed,
            "only_in_baseline": only_baseline,
            "only_in_current": only_current,
            "regressions": len(changed) + len(only_baseline)}


def resolutions_from_cbom(inv) -> list:
    """Pull the manifest collector's recorded alias resolutions out of a loaded
    Inventory's metadata, de-duplicated across manifests by (package, version,
    ecosystem). Empty when the scan did no manifest discovery."""
    seen = {}
    for c in inv.meta.get("collectors", []):
        if c.get("name") != "manifests":
            continue
        for r in c.get("alias_resolutions", []):
            key = (r.get("package"), r.get("version"), r.get("ecosystem"))
            seen.setdefault(key, r)
    return list(seen.values())


def wrapper_coverage(resolutions: list) -> dict:
    """Measure how much of the discovered dependency surface is resolved through
    *wrapper* packages, whose version does not track the underlying library.

    A high wrapper share means version-gated capabilities are withheld for many
    components (fail-closed), so the PQC assessment is conservative — it may miss
    real PQC readiness (e.g. pyOpenSSL over an OpenSSL 3.5 that does ship ML-KEM).
    `wrapper_pct` is measured over the *mapped* packages (those that resolve to a
    provider-map component); unmapped packages attribute no capabilities either
    way, so they are reported but excluded from the ratio."""
    discovered = len(resolutions)
    mapped = [r for r in resolutions if r.get("mapped", True)]
    wrappers = [r for r in mapped if r.get("wrapper")]
    unmapped = [r for r in resolutions if not r.get("mapped", True)]
    pct = round(100.0 * len(wrappers) / len(mapped), 1) if mapped else 0.0
    return {
        "discovered": discovered,
        "mapped": len(mapped),
        "wrappers": len(wrappers),
        "unmapped": len(unmapped),
        "wrapper_pct": pct,
        "wrapper_packages": sorted(f"{r.get('package')}@{r.get('version')}"
                                   for r in wrappers),
    }
