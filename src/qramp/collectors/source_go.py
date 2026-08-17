# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""SourceCollector (Go) — interprets matches from a declarative ``.scm`` query
file (``queries/go.scm``) into CryptoAssets.

Structural detection lives in the query file; this module keeps the semantic
mapping (package.Function -> primitive/algorithm, JCA-style key sizes from
positional int args, curve from a nested ``elliptic.PXXX()`` call, and
``tls.*`` constants).
"""
from __future__ import annotations

import os

from ..model import Inventory, Occurrence
from . import register
from .tsquery import QueryEngine, get_engine

_ENGINE = QueryEngine("go")
HAVE_TS_GO = _ENGINE.available

# (package, Function) -> (primitive, algorithm, default_key_length, key_arg_index or None)
CALL_MAP = {
    ("md5", "Sum"): ("hash", "md5", None, None),
    ("md5", "New"): ("hash", "md5", None, None),
    ("sha1", "Sum"): ("hash", "sha1", None, None),
    ("sha1", "New"): ("hash", "sha1", None, None),
    ("sha256", "Sum256"): ("hash", "sha2-256", None, None),
    ("sha256", "New"): ("hash", "sha2-256", None, None),
    ("sha512", "Sum512"): ("hash", "sha2-512", None, None),
    ("sha512", "New"): ("hash", "sha2-512", None, None),
    ("des", "NewCipher"): ("symmetric-cipher", "des", 56, None),
    ("des", "NewTripleDESCipher"): ("symmetric-cipher", "3des", 112, None),
    ("rc4", "NewCipher"): ("symmetric-cipher", "rc4", 128, None),
    ("aes", "NewCipher"): ("symmetric-cipher", "aes", None, None),
    ("rsa", "GenerateKey"): ("pk-encryption", "rsa", None, 1),
    ("dsa", "GenerateKey"): ("signature", "dsa", 1024, None),
    ("dsa", "GenerateParameters"): ("signature", "dsa", 1024, None),
    ("ecdsa", "GenerateKey"): ("signature", "ecdsa", None, None),
    ("ed25519", "GenerateKey"): ("signature", "ed25519", 256, None),
}

CURVE_MAP = {
    "P224": ("nistp224", 224), "P256": ("nistp256", 256),
    "P384": ("nistp384", 384), "P521": ("nistp521", 521),
}

TLS_VERSION_CONST = {
    "VersionSSL30": ("ssl", "3.0"),
    "VersionTLS10": ("tls", "1.0"), "VersionTLS11": ("tls", "1.1"),
    "VersionTLS12": ("tls", "1.2"), "VersionTLS13": ("tls", "1.3"),
}


def _suite_assets(const: str):
    c = const.upper()
    out = []
    if "3DES" in c:
        out.append(("symmetric-cipher", "3des", 112, "cbc"))
    elif "RC4" in c:
        out.append(("symmetric-cipher", "rc4", 128, ""))
    elif "AES_128" in c:
        out.append(("symmetric-cipher", "aes", 128, "gcm" if "GCM" in c else "cbc"))
    elif "AES_256" in c:
        out.append(("symmetric-cipher", "aes", 256, "gcm" if "GCM" in c else "cbc"))
    if "ECDHE" in c:
        out.append(("key-agreement", "ecdh", None, ""))
    elif c.startswith("TLS_RSA") or "_RSA_WITH" in c:
        # static-RSA key transport: RSA is the KEY EXCHANGE, not just auth.
        # No forward secrecy; Shor-broken key transport. Modelled as a
        # key-agreement asset so it is distinct from RSA keygen/signature and
        # routes to decommissioning.
        out.append(("key-agreement", "rsa", None, ""))
    if "_RSA_" in c:
        out.append(("signature", "rsa", None, ""))
    elif "_ECDSA_" in c:
        out.append(("signature", "ecdsa", None, ""))
    return out


def _int_arg(args_node, index, src):
    positional = [c for c in args_node.children if c.type not in ("(", ")", ",")]
    if index < len(positional) and positional[index].type == "int_literal":
        try:
            return int(src[positional[index].start_byte:positional[index].end_byte]
                       .decode().replace("_", ""))
        except ValueError:
            return None
    return None


def _curve_from_args(args_node, src):
    for c in args_node.children:
        if c.type == "call_expression":
            fn = c.child_by_field_name("function")
            if fn is not None and fn.type == "selector_expression":
                field = fn.child_by_field_name("field")
                member = src[field.start_byte:field.end_byte].decode() if field else ""
                if member in CURVE_MAP:
                    return CURVE_MAP[member]
    return None, None


@register("source-go")
def run(inv: Inventory, source_dir: str, owner_map: dict | None = None,
        query_dir: str | None = None, **_) -> dict:
    owner_map = owner_map or {}
    engine = get_engine("go", query_dir) if query_dir else _ENGINE
    if not engine.available:
        stats = {"files": 0, "call_sites": 0, "skipped": engine.reason}
        inv.record_collector("source-go", stats)
        return stats

    files = hits = 0
    for root, _d, fns in os.walk(source_dir):
        if any(p in root for p in (".git", "vendor", "node_modules")):
            continue
        for fn in fns:
            if not fn.endswith(".go"):
                continue
            path = os.path.join(root, fn)
            src = open(path, "rb").read()
            files += 1
            hits += _interpret(inv, src, path, owner_map.get(fn), engine)
    stats = {"files": files, "call_sites": hits,
             "query_hash": engine.query_source_hash(),
             "query_sources": engine.describe_sources()}
    inv.record_collector("source-go", stats)
    return stats


def _occ(line, path, owner, evidence, confidence=1.0, tags=None):
    return Occurrence(collector="source-go", locator=f"{path}:{line}",
                      evidence=evidence, confidence=confidence,
                      owner=owner, tags=tags or [])


def _interpret(inv, src, path, owner, engine=None) -> int:
    engine = engine or _ENGINE
    hits = 0
    for m in engine.run(src):
        if m.settings.get("primitive") and m.settings.get("algorithm"):
            hits += _emit_site(inv, m, path, owner)
            continue
        if "fn" in m.caps:
            hits += _emit_call(inv, m, src, path, owner)
        elif "const" in m.caps:
            hits += _emit_tls_const(inv, m, path, owner)
    return hits


def _emit_call(inv, m, src, path, owner) -> int:
    pkg = m.caps.get("pkg", "")
    member = m.caps.get("fn", "")
    entry = CALL_MAP.get((pkg, member))
    if entry is None:
        return 0
    primitive, algorithm, kl_default, key_idx = entry
    key_length = kl_default
    params = ""
    args_node = m.nodes.get("args")

    if key_idx is not None and args_node is not None:
        n = _int_arg(args_node, key_idx, src)
        if n is not None:
            key_length = n
        else:
            inv.observe(primitive, algorithm,
                        _occ(m.line, path, owner,
                             f"{algorithm} key size computed at run time",
                             confidence=0.5, tags=["indeterminate"]))
            return 1

    if algorithm == "ecdsa" and args_node is not None:
        p, kl = _curve_from_args(args_node, src)
        if p:
            params, key_length = p, kl

    inv.observe(primitive, algorithm,
                _occ(m.line, path, owner, f"{pkg}.{member}(...)"
                     + (f", key size {key_length}" if key_length else "")
                     + (f", curve {params}" if params else "")),
                params=params, key_length=key_length)
    return 1


def _emit_tls_const(inv, m, path, owner) -> int:
    member = m.caps.get("const", "")
    if member in TLS_VERSION_CONST:
        alg, ver = TLS_VERSION_CONST[member]
        inv.observe("protocol", alg,
                    _occ(m.line, path, owner, f"tls.{member} configured"), params=ver)
        return 1
    if member.startswith("TLS_") and ("_WITH_" in member.upper() or "AES" in member.upper()):
        assets = _suite_assets(member)
        for primitive, algorithm, kl, mode in assets:
            inv.observe(primitive, algorithm,
                        _occ(m.line, path, owner, f"cipher suite {member}", confidence=0.8),
                        key_length=kl, mode=mode)
        return 1 if assets else 0
    return 0


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
