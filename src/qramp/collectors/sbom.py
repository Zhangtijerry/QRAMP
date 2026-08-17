# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""SBOMCollector — ingests CycloneDX JSON and maps components to the
cryptographic capabilities they ship, using a curated, version-aware mapping
file that is versioned data, not code. A provider-map entry may gate a
capability on the component version (e.g. OpenSSL ships ML-KEM only in 3.5+), so
the same library resolves to different capabilities depending on its version.
Unmapped components are recorded as unknown rather than silently dropped.
"""
from __future__ import annotations

import json
import os

import yaml

from ..model import Inventory, Occurrence
from . import register
from ..providermap import resolve

DEFAULT_MAP = os.path.join(os.path.dirname(__file__), "..", "data", "provider-map.yaml")


@register("sbom")
def run(inv: Inventory, sbom_path: str, provider_map: str | None = None, **_) -> dict:
    mapping = yaml.safe_load(open(provider_map or DEFAULT_MAP, encoding="utf-8"))
    entries = {e["component"].lower(): e for e in mapping.get("components", [])}

    doc = json.load(open(sbom_path, encoding="utf-8"))
    mapped = unmapped = edges = version_gated = 0
    for comp in doc.get("components", []):
        name = (comp.get("name") or "").lower()
        version = comp.get("version", "?")
        purl = comp.get("purl", "")
        ctype = comp.get("type", "library")
        locator = f"{sbom_path}#{name}@{version}"
        entry = entries.get(name)
        if not entry:
            unmapped += 1
            continue
        mapped += 1
        # register the software component even before wiring provides edges
        component = inv.component(name, version, purl=purl, ctype=ctype)
        # version-aware resolution: only the capabilities this version ships
        for prov in resolve(entry, version):
            gate = f" (version {prov.version_gate})" if prov.version_gate else ""
            if prov.version_gate:
                version_gated += 1
            asset = inv.observe(prov.primitive, prov.algorithm,
                                Occurrence(collector="sbom", locator=locator,
                                           evidence=f"component {name}@{version} ships "
                                                    f"{prov.algorithm}{gate}",
                                           confidence=prov.confidence),
                                params=prov.params, key_length=prov.key_length)
            inv.provide(component, asset)          # record the provides edge
            edges += 1
    stats = {"components_mapped": mapped, "components_unmapped": unmapped,
             "provides_edges": edges, "version_gated_edges": version_gated,
             "map_version": mapping.get("version", "?")}
    inv.record_collector("sbom", stats)
    return stats
