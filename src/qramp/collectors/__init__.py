# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.collectors — Layer 1 plugin registry.

Third-party collectors register through the ``qramp.collectors`` entry-point
group; built-ins register by importing this package. Every collector is a
callable ``run(inventory, **kwargs) -> dict`` returning its stats. Collectors
are strictly read-only.
"""
from __future__ import annotations

from importlib.metadata import entry_points

_REGISTRY: dict[str, callable] = {}


def register(name: str):
    def deco(fn):
        _REGISTRY[name] = fn
        return fn
    return deco


def get(name: str):
    if name not in _REGISTRY:
        _load_entry_points()
    return _REGISTRY[name]


def available() -> list[str]:
    _load_entry_points()
    return sorted(_REGISTRY)


def _load_entry_points() -> None:
    try:
        for ep in entry_points(group="qramp.collectors"):
            if ep.name not in _REGISTRY:
                _REGISTRY[ep.name] = ep.load()
    except Exception:
        pass


# built-ins
from . import certs, configs, source_py, source_java, source_go, source_rust, source_c, sbom, tls, manifests  # noqa: E402,F401
