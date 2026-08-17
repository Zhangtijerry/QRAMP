# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.collectors.manifests — discover crypto-relevant components from package
manifests, so a scan does not need a hand-produced CycloneDX SBOM.

Most projects already declare their dependencies in an ecosystem manifest —
`package-lock.json`, `requirements.txt`, `go.mod`/`go.sum`, `pom.xml`,
`Cargo.lock`. This collector walks a source tree, parses whichever manifests it
finds, and feeds the resulting (name, version) pairs through the same
version-aware provider map the SBOM collector uses, so a deployed OpenSSL or
BouncyCastle is discovered and mapped to the capabilities it ships without any
extra configuration.

The parsers are deliberately dependency-free and lenient: an ecosystem lock file
that QRAMP cannot fully parse contributes what it can rather than failing the
scan, and a manifest is only consulted for the handful of packages the provider
map actually knows about (a manifest lists hundreds of dependencies; only the
cryptographic providers matter here). Every discovered component keeps a
`path:manifest` locator so its origin is auditable, and the component name is
normalised to the provider map's key (e.g. the Maven artifact `bcprov-jdk18on`
and the PyPI package `pyOpenSSL` both resolve to their underlying library).
"""
from __future__ import annotations

import json
import os
import re

import yaml

from ..model import Inventory, Occurrence
from . import register
from ..providermap import resolve

DEFAULT_MAP = os.path.join(os.path.dirname(__file__), "..", "data", "provider-map.yaml")

# manifest filename -> parser name
MANIFEST_FILES = {
    "package-lock.json": "npm",
    "requirements.txt": "pip",
    "go.mod": "gomod",
    "go.sum": "gosum",
    "pom.xml": "maven",
    "Cargo.lock": "cargo",
    "Cargo.toml": "cargotoml",
}

# package-name aliases are versioned data (data/manifest-aliases.yaml), loaded
# lazily so a custom alias map can be supplied per scan. Each value is
# (component_key, version_tracks_library); see the YAML for the wrapper rationale.
_ALIAS_CACHE: dict | None = None


def _aliases(alias_map: str | None = None) -> dict:
    global _ALIAS_CACHE
    if alias_map is not None:                      # explicit path: never cache
        from ..aliasmap import load as _load_aliases
        return _load_aliases(alias_map)
    if _ALIAS_CACHE is None:
        from ..aliasmap import load as _load_aliases
        try:
            _ALIAS_CACHE = _load_aliases()
        except Exception:
            _ALIAS_CACHE = {}
    return _ALIAS_CACHE


def _norm(name: str, aliases: dict):
    """Return (component_key, version_tracks_library). Unknown names map to
    themselves and are assumed to track their own version."""
    n = name.strip().lower()
    return aliases.get(n, (n, True))


# --- per-ecosystem parsers: each returns a list of (name, version, path) -------
def parse_npm(path: str) -> list[tuple[str, str]]:
    """package-lock.json — v2/v3 use `packages`, v1 uses `dependencies`."""
    out = []
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except Exception:
        return out
    pkgs = doc.get("packages")
    if isinstance(pkgs, dict):
        for key, meta in pkgs.items():
            if not key:                       # "" is the root package
                continue
            name = key.split("node_modules/")[-1]
            ver = (meta or {}).get("version", "?")
            out.append((name, ver))
    deps = doc.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            out.append((name, (meta or {}).get("version", "?")))
    return out


_PIP_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)")


def parse_pip(path: str) -> list[tuple[str, str]]:
    """requirements.txt — pinned `name==version` lines (loose pins are skipped
    because the version drives the capability resolution)."""
    out = []
    try:
        for raw in open(path, encoding="utf-8"):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = _PIP_LINE.match(line)
            if m:
                out.append((m.group(1), m.group(2)))
    except Exception:
        pass
    return out


_GOMOD_REQ = re.compile(r"^\s*([^\s]+)\s+v([^\s/]+)")


def parse_gomod(path: str) -> list[tuple[str, str]]:
    """go.mod — `require` directives (single-line and block form)."""
    out = []
    try:
        in_block = False
        for raw in open(path, encoding="utf-8"):
            line = raw.strip()
            if line.startswith("require ("):
                in_block = True
                continue
            if in_block and line == ")":
                in_block = False
                continue
            target = line
            if line.startswith("require "):
                target = line[len("require "):].strip()
            if in_block or line.startswith("require "):
                m = _GOMOD_REQ.match(target)
                if m:
                    out.append((m.group(1), m.group(2)))
    except Exception:
        pass
    return out


def parse_gosum(path: str) -> list[tuple[str, str]]:
    """go.sum — `module vX.Y.Z hash` lines (dedup, ignore /go.mod entries)."""
    out = []
    seen = set()
    try:
        for raw in open(path, encoding="utf-8"):
            parts = raw.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                name = parts[0]
                ver = parts[1].split("/")[0].lstrip("v")
                if (name, ver) not in seen:
                    seen.add((name, ver))
                    out.append((name, ver))
    except Exception:
        pass
    return out


def parse_maven(path: str) -> list[tuple[str, str]]:
    """pom.xml — <dependency> groupId/artifactId/version. Uses the stdlib XML
    parser; ignores namespaces by matching on local tag names."""
    out = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(path)
        root = tree.getroot()

        def local(tag):
            return tag.rsplit("}", 1)[-1]

        for dep in root.iter():
            if local(dep.tag) != "dependency":
                continue
            gid = aid = ver = None
            for child in dep:
                lt = local(child.tag)
                if lt == "groupId":
                    gid = (child.text or "").strip()
                elif lt == "artifactId":
                    aid = (child.text or "").strip()
                elif lt == "version":
                    ver = (child.text or "").strip()
            if aid and ver and not ver.startswith("${"):
                # prefer artifactId; fall back to groupId for org.* aliases
                out.append((aid, ver))
                if gid:
                    out.append((gid, ver))
    except Exception:
        pass
    return out


def parse_cargo(path: str) -> list[tuple[str, str]]:
    """Cargo.lock — TOML `[[package]]` blocks with name/version."""
    out = []
    try:
        name = ver = None
        for raw in open(path, encoding="utf-8"):
            line = raw.strip()
            if line == "[[package]]":
                name = ver = None
                continue
            m = re.match(r'name\s*=\s*"([^"]+)"', line)
            if m:
                name = m.group(1)
            m = re.match(r'version\s*=\s*"([^"]+)"', line)
            if m:
                ver = m.group(1)
            if name and ver:
                out.append((name, ver))
                name = ver = None
    except Exception:
        pass
    return out


def parse_cargotoml(path: str) -> list[tuple[str, str]]:
    """Cargo.toml — [dependencies] name = "version" (loose; Cargo.lock is
    preferred when present)."""
    out = []
    try:
        in_deps = False
        for raw in open(path, encoding="utf-8"):
            line = raw.strip()
            if line.startswith("["):
                in_deps = line in ("[dependencies]", "[dev-dependencies]")
                continue
            if in_deps:
                m = re.match(r'([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"', line)
                if m:
                    out.append((m.group(1), m.group(2)))
    except Exception:
        pass
    return out


_PARSERS = {
    "npm": parse_npm, "pip": parse_pip, "gomod": parse_gomod,
    "gosum": parse_gosum, "maven": parse_maven, "cargo": parse_cargo,
    "cargotoml": parse_cargotoml,
}


def discover(source_dir: str) -> list[tuple[str, str, str, str]]:
    """Walk `source_dir` for known manifests. Returns (name, version, ecosystem,
    path) tuples for every dependency found (unfiltered)."""
    found = []
    for root, dirs, files in os.walk(source_dir):
        # skip vendored / dependency directories to avoid nested manifests
        dirs[:] = [d for d in dirs
                   if d not in ("node_modules", "vendor", "target", ".git",
                                "__pycache__", "site-packages")]
        for fn in files:
            eco = MANIFEST_FILES.get(fn)
            if not eco:
                continue
            path = os.path.join(root, fn)
            for name, ver in _PARSERS[eco](path):
                found.append((name, ver, eco, path))
    return found


@register("manifests")
def run(inv: Inventory, source_dir: str, provider_map: str | None = None,
        alias_map: str | None = None, **_) -> dict:
    """Discover components from package manifests and map the crypto-relevant
    ones through the provider map (same resolution the SBOM collector uses)."""
    mapping = yaml.safe_load(open(provider_map or DEFAULT_MAP, encoding="utf-8"))
    entries = {e["component"].lower(): e for e in mapping.get("components", [])}
    aliases = _aliases(alias_map)

    discovered = discover(source_dir)
    manifests_seen = {path for _, _, _, path in discovered}
    mapped = edges = version_gated = wrappers = 0
    seen_components = set()
    by_ecosystem: dict = {}
    resolutions: list = []          # audit trail: package -> component per manifest
    for name, version, eco, path in discovered:
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
        key, tracks_version = _norm(name, aliases)
        entry = entries.get(key)
        # record every discovered crypto-relevant package's resolution, including
        # ones with no provider-map entry (mapped=False) so the audit shows what
        # was seen but could not be attributed.
        rel_path = os.path.relpath(path, source_dir)
        resolutions.append({
            "package": name, "version": version, "ecosystem": eco,
            "component": key, "wrapper": not tracks_version,
            "mapped": entry is not None, "manifest": rel_path,
        })
        if not entry:
            continue
        # a wrapper/binding package's version does not track the underlying
        # library, so resolving version gates against it would be wrong. Record
        # the component at its declared version for provenance, but resolve
        # capabilities at an UNKNOWN version so the gates fail closed (baseline
        # capabilities only, no version-gated PQC claims).
        resolve_version = version if tracks_version else "?"
        if not tracks_version:
            wrappers += 1
        # de-dup: the same library may appear in several manifests/versions;
        # take the first (name, version) we see per component key + version.
        dedup = (key, version)
        if dedup in seen_components:
            continue
        seen_components.add(dedup)
        mapped += 1
        rel = os.path.relpath(path, source_dir)
        disp_version = version if tracks_version else f"{version}~wrapper"
        component = inv.component(key, disp_version, ctype="library")
        note = "" if tracks_version else (
            f" [wrapper {name}@{version}; underlying library version unknown, "
            f"version-gated capabilities withheld]")
        for prov in resolve(entry, resolve_version):
            gate = f" (version {prov.version_gate})" if prov.version_gate else ""
            if prov.version_gate:
                version_gated += 1
            asset = inv.observe(
                prov.primitive, prov.algorithm,
                Occurrence(collector="manifests", locator=f"{rel}#{key}@{version}",
                           evidence=f"{eco} manifest declares {name}@{version} "
                                    f"which ships {prov.algorithm}{gate}{note}",
                           confidence=prov.confidence),
                params=prov.params, key_length=prov.key_length)
            inv.provide(component, asset)
            edges += 1
    stats = {"manifests_found": len(manifests_seen),
             "dependencies_seen": len(discovered),
             "components_mapped": mapped, "wrapper_components": wrappers,
             "provides_edges": edges, "version_gated_edges": version_gated,
             "by_ecosystem": by_ecosystem,
             "alias_resolutions": resolutions,
             "map_version": mapping.get("version", "?")}
    inv.record_collector("manifests", stats)
    return stats
