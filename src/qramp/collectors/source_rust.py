# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""SourceCollector (Rust) — interprets matches from a declarative ``.scm``
query file (``queries/rust.scm``) into CryptoAssets.

Structural detection lives in the query file; this module keeps the semantic
mapping for the RustCrypto ecosystem and ring: type names like ``Md5``,
``RsaPrivateKey``, ``Aes256Gcm``, ``Des`` -> normalised assets, with key sizes
lifted from integer arguments (e.g. ``RsaPrivateKey::new(rng, 2048)``).

Like the other source collectors it is query-driven, supports site overrides
via ``#set!`` directives, records the query hash + provenance, and degrades to
yielding nothing (with a reason) when the grammar is unavailable.
"""
from __future__ import annotations

import os

from ..model import Inventory, Occurrence
from . import register
from .tsquery import QueryEngine, get_engine

_ENGINE = QueryEngine("rust")
HAVE_TS_RUST = _ENGINE.available

# type name (last path segment before ::method) -> (primitive, algorithm,
# default_key_length, key_arg_index or None)
TYPE_MAP = {
    "Md5": ("hash", "md5", None, None),
    "Md2": ("hash", "md2", None, None),
    "Sha1": ("hash", "sha1", None, None),
    "Sha224": ("hash", "sha2-224", None, None),
    "Sha256": ("hash", "sha2-256", None, None),
    "Sha384": ("hash", "sha2-384", None, None),
    "Sha512": ("hash", "sha2-512", None, None),
    "Sha3_256": ("hash", "sha3-256", None, None),
    "Sha3_512": ("hash", "sha3-512", None, None),
    "Des": ("symmetric-cipher", "des", 56, None),
    "TdesEde3": ("symmetric-cipher", "3des", 112, None),
    "DesX": ("symmetric-cipher", "des", 56, None),
    "Rc4": ("symmetric-cipher", "rc4", 128, None),
    "Rc2": ("symmetric-cipher", "rc2", None, None),
    "Blowfish": ("symmetric-cipher", "blowfish", None, None),
    "Aes128": ("symmetric-cipher", "aes", 128, None),
    "Aes192": ("symmetric-cipher", "aes", 192, None),
    "Aes256": ("symmetric-cipher", "aes", 256, None),
    "Aes128Gcm": ("symmetric-cipher", "aes", 128, None),
    "Aes256Gcm": ("symmetric-cipher", "aes", 256, None),
    "ChaCha20Poly1305": ("symmetric-cipher", "chacha20", 256, None),
    "RsaPrivateKey": ("pk-encryption", "rsa", None, 1),
    "RsaPublicKey": ("pk-encryption", "rsa", None, None),
    "DsaPrivateKey": ("signature", "dsa", None, None),
    "SigningKey": ("signature", "ecdsa", None, None),   # ecdsa/ed25519 crate SigningKey
    "Ed25519": ("signature", "ed25519", 256, None),
    "MlKem512": ("key-agreement", "ml-kem", None, None),
    "MlKem768": ("key-agreement", "ml-kem", None, None),
    "MlKem1024": ("key-agreement", "ml-kem", None, None),
    "MlDsa": ("signature", "ml-dsa", None, None),
}

# crate name (from `use <crate>::...`) -> the mode's alg if the type is unknown,
# so a bare `use md5::Md5;` still yields a low-confidence signal.
CRATE_HINT = {
    "md5": ("hash", "md5"), "md2": ("hash", "md2"), "sha1": ("hash", "sha1"),
    "des": ("symmetric-cipher", "des"), "rc4": ("symmetric-cipher", "rc4"),
    "rsa": ("pk-encryption", "rsa"),
}


def _type_of(path: str) -> str:
    """Given a scoped path like `des::Des::new_from_slice`, return the type
    segment (the one immediately before the final ::method) — here `Des`."""
    segs = path.split("::")
    if len(segs) >= 2:
        return segs[-2]
    return segs[0]


def _int_arg(args_node, index, src):
    import re
    positional = [c for c in args_node.children
                  if c.type not in ("(", ")", ",")]
    if index < len(positional) and positional[index].type == "integer_literal":
        raw = src[positional[index].start_byte:positional[index].end_byte].decode()
        # strip a trailing Rust integer type suffix (u8/i32/usize/...) and any
        # digit separators, keeping the numeric value intact.
        m = re.match(r"(\d[\d_]*)", raw)
        if m:
            try:
                return int(m.group(1).replace("_", ""))
            except ValueError:
                return None
    return None


@register("source-rust")
def run(inv: Inventory, source_dir: str, owner_map: dict | None = None,
        query_dir: str | None = None, **_) -> dict:
    owner_map = owner_map or {}
    engine = get_engine("rust", query_dir) if query_dir else _ENGINE
    if not engine.available:
        stats = {"files": 0, "call_sites": 0, "skipped": engine.reason}
        inv.record_collector("source-rust", stats)
        return stats

    files = hits = 0
    for root, _d, fns in os.walk(source_dir):
        if any(p in root for p in (".git", "target", "node_modules")):
            continue
        for fn in fns:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(root, fn)
            src = open(path, "rb").read()
            files += 1
            hits += _interpret(inv, src, path, owner_map.get(fn), engine)
    stats = {"files": files, "call_sites": hits,
             "query_hash": engine.query_source_hash(),
             "query_sources": engine.describe_sources()}
    inv.record_collector("source-rust", stats)
    return stats


def _occ(line, path, owner, evidence, confidence=1.0, tags=None):
    return Occurrence(collector="source-rust", locator=f"{path}:{line}",
                      evidence=evidence, confidence=confidence,
                      owner=owner, tags=tags or [])


def _interpret(inv, src, path, owner, engine=None) -> int:
    engine = engine or _ENGINE
    hits = 0
    call_types = set()          # types already seen as calls (to dedupe use-hints)
    calls = []
    uses = []
    for m in engine.run(src):
        if m.settings.get("primitive") and m.settings.get("algorithm"):
            hits += _emit_site(inv, m, path, owner)
            continue
        if "path" in m.caps:
            calls.append(m)
        elif "crate" in m.caps:
            uses.append(m)
    for m in calls:
        t = _type_of(m.caps["path"])
        call_types.add(t)
        hits += _emit_call(inv, m, t, src, path, owner)
    for m in uses:
        # only surface a use-hint if we did not already see a concrete call for
        # that crate's type (avoids double-counting), and the type is unknown.
        hits += _emit_use(inv, m, call_types, path, owner)
    return hits


def _emit_call(inv, m, typename, src, path, owner) -> int:
    entry = TYPE_MAP.get(typename)
    if entry is None:
        return 0
    primitive, algorithm, kl_default, key_idx = entry
    key_length = kl_default
    if key_idx is not None:
        n = _int_arg(m.nodes.get("args"), key_idx, src) if m.nodes.get("args") else None
        if n is not None:
            key_length = n
        else:
            inv.observe(primitive, algorithm,
                        _occ(m.line, path, owner,
                             f"{algorithm} key size computed at run time",
                             confidence=0.5, tags=["indeterminate"]))
            return 1
    inv.observe(primitive, algorithm,
                _occ(m.line, path, owner, f"{m.caps['path']}(...)"
                     + (f", key size {key_length}" if key_length else "")),
                key_length=key_length)
    return 1


def _emit_use(inv, m, call_types, path, owner) -> int:
    crate = m.caps.get("crate", "")
    item = m.caps.get("item", "")
    if item in call_types or item in TYPE_MAP:
        return 0                        # a concrete call already covers this
    hint = CRATE_HINT.get(crate)
    if hint is None:
        return 0
    primitive, algorithm = hint
    inv.observe(primitive, algorithm,
                _occ(m.line, path, owner, f"use {crate}::{item} (import only)",
                     confidence=0.4, tags=["indeterminate"]))
    return 1


def _emit_site(inv, m, path, owner) -> int:
    """Emit an asset purely from site-declared #set! metadata on the pattern."""
    st = m.settings
    kl = st.get("key_length")
    try:
        kl = int(kl) if kl is not None else None
    except (TypeError, ValueError):
        kl = None
    inv.observe(st["primitive"], st["algorithm"],
                _occ(m.line, path, owner,
                     st.get("evidence", "site query match"),
                     confidence=float(st.get("confidence", 1.0))),
                params=st.get("params", ""), key_length=kl, mode=st.get("mode", ""))
    return 1
