# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""QRAMP — cryptographic asset inventory and quantum-resistant migration planning."""
__version__ = "0.1.1"

from .model import Inventory, CryptoAsset, Occurrence, diff  # noqa: F401
from . import collectors, assess, plan, report  # noqa: F401


def scan(inventory: Inventory, **sources) -> Inventory:
    """Run the requested collectors against an inventory. Recognised kwargs:
    source_dir, sbom_path, cert_dir, config_dir, and (scope_path + scope_key)."""
    import os
    for key in ("source_dir", "manifests_dir", "cert_dir", "config_dir"):
        if sources.get(key) and not os.path.isdir(sources[key]):
            raise ValueError(f"{key} directory does not exist: {sources[key]}")
    if sources.get("sbom_path") and not os.path.isfile(sources["sbom_path"]):
        raise ValueError(f"SBOM file does not exist: {sources['sbom_path']}")
    if sources.get("source_dir"):
        collectors.get("source-py")(inventory, source_dir=sources["source_dir"],
                                    owner_map=sources.get("owner_map"),
                                    query_dir=sources.get("query_dir"))
        collectors.get("source-java")(inventory, source_dir=sources["source_dir"],
                                      owner_map=sources.get("owner_map"),
                                      query_dir=sources.get("query_dir"))
        collectors.get("source-go")(inventory, source_dir=sources["source_dir"],
                                    owner_map=sources.get("owner_map"),
                                    query_dir=sources.get("query_dir"))
        collectors.get("source-rust")(inventory, source_dir=sources["source_dir"],
                                      owner_map=sources.get("owner_map"),
                                      query_dir=sources.get("query_dir"))
        collectors.get("source-c")(inventory, source_dir=sources["source_dir"],
                                   owner_map=sources.get("owner_map"),
                                   query_dir=sources.get("query_dir"))
    if sources.get("sbom_path"):
        collectors.get("sbom")(inventory, sbom_path=sources["sbom_path"],
                               provider_map=sources.get("provider_map"))
    if sources.get("manifests_dir"):
        collectors.get("manifests")(inventory, source_dir=sources["manifests_dir"],
                                    provider_map=sources.get("provider_map"),
                                    alias_map=sources.get("alias_map"))
    if sources.get("cert_dir"):
        collectors.get("certs")(inventory, cert_dir=sources["cert_dir"],
                                owner_map=sources.get("owner_map"))
    if sources.get("config_dir"):
        collectors.get("configs")(inventory, config_dir=sources["config_dir"],
                                  owner_map=sources.get("owner_map"))
    if sources.get("scope_path") and sources.get("scope_key"):
        collectors.get("tls")(inventory, scope_path=sources["scope_path"],
                              scope_key=sources["scope_key"])
    return inventory
