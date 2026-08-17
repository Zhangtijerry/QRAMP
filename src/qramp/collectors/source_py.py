# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""SourceCollector (Python) — interprets matches from a declarative ``.scm``
query file (``queries/python.scm``) into CryptoAssets.

Structural detection lives in the query file; this module keeps the semantic
mapping: hashlib digests, pycryptodome ciphers, cryptography keygens (with
literal key sizes and EC curves) and ``ssl.PROTOCOL_*`` constants.
"""
from __future__ import annotations

import os

from ..model import Inventory, Occurrence
from . import register
from .tsquery import QueryEngine, get_engine

_ENGINE = QueryEngine("python")
HAVE_TS_PY = _ENGINE.available

HASHLIB_WEAK = {"md5": "md5", "sha1": "sha1"}
HASHLIB_OK = {"sha256": "sha2-256", "sha384": "sha2-384", "sha512": "sha2-512",
              "sha3_256": "sha3-256", "sha3_512": "sha3-512"}
PYCRYPTO_CIPHERS = {"DES": ("des", 56), "DES3": ("3des", 112), "ARC4": ("rc4", 128),
                    "AES": ("aes", None), "Blowfish": ("blowfish", None)}
SSL_CONST = {"PROTOCOL_TLSv1": ("tls", "1.0"), "PROTOCOL_TLSv1_1": ("tls", "1.1"),
             "PROTOCOL_SSLv3": ("ssl", "3.0")}


def _node_text(node, src):
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _qualname(node, src):
    """Dotted name for an attribute/identifier node, e.g. Crypto.Cipher.AES."""
    return _node_text(node, src)


def _string_args(args_node, src):
    """Return list of string-literal argument values (unquoted)."""
    out = []
    for a in args_node.children:
        if a.type == "string":
            for c in a.children:
                if c.type == "string_content":
                    out.append(_node_text(c, src))
    return out


def _kw_int(args_node, name, src):
    for a in args_node.children:
        if a.type == "keyword_argument":
            n = a.child_by_field_name("name")
            v = a.child_by_field_name("value")
            if n is not None and v is not None and _node_text(n, src) == name \
                    and v.type == "integer":
                try:
                    return int(_node_text(v, src))
                except ValueError:
                    return None
    return None


def _arg_qualnames(args_node, src):
    """Qualified names of positional + keyword-value args (for MODE_*, curves)."""
    names = []
    for a in args_node.children:
        if a.type in ("attribute", "identifier"):
            names.append(_node_text(a, src))
        elif a.type == "keyword_argument":
            v = a.child_by_field_name("value")
            if v is not None and v.type in ("attribute", "identifier", "call"):
                names.append(_node_text(v, src))
        elif a.type == "call":
            fn = a.child_by_field_name("function")
            if fn is not None:
                names.append(_node_text(fn, src))
    return names


@register("source-py")
def run(inv: Inventory, source_dir: str, owner_map: dict | None = None,
        query_dir: str | None = None, **_) -> dict:
    owner_map = owner_map or {}
    engine = get_engine("python", query_dir) if query_dir else _ENGINE
    if not engine.available:
        stats = {"files": 0, "call_sites": 0, "skipped": engine.reason}
        inv.record_collector("source-py", stats)
        return stats

    files = hits = 0
    for root, _d, fns in os.walk(source_dir):
        if any(p in root for p in (".git", "venv", "__pycache__", "node_modules")):
            continue
        for fn in fns:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            src = open(path, "rb").read()
            files += 1
            hits += _interpret(inv, src, path, owner_map.get(fn), engine)
    stats = {"files": files, "call_sites": hits,
             "query_hash": engine.query_source_hash(),
             "query_sources": engine.describe_sources()}
    inv.record_collector("source-py", stats)
    return stats


def _occ(line, path, owner, evidence, confidence=1.0, tags=None):
    return Occurrence(collector="source-py", locator=f"{path}:{line}",
                      evidence=evidence, confidence=confidence,
                      owner=owner, tags=tags or [])


def _interpret(inv, src, path, owner, engine=None) -> int:
    engine = engine or _ENGINE
    hits = 0
    seen_attr = set()
    for m in engine.run(src):
        # Site-declared matches: a #set! "primitive"/"algorithm" pair on the
        # pattern classifies the asset directly, so a site can add detection
        # entirely in the .scm file with no interpreter code.
        if m.settings.get("primitive") and m.settings.get("algorithm"):
            hits += _emit_site(inv, m, path, owner)
            continue
        if "attr" in m.caps and "args" in m.nodes:
            hits += _emit_call(inv, m, src, path, owner)
        elif "cattr" in m.caps:
            key = (m.line, m.caps.get("cobj"), m.caps.get("cattr"))
            if key in seen_attr:
                continue
            seen_attr.add(key)
            hits += _emit_attr(inv, m, path, owner)
    return hits


def _emit_site(inv, m, path, owner) -> int:
    """Emit an asset purely from site-declared #set! metadata on the pattern."""
    s = m.settings
    kl = s.get("key_length")
    try:
        kl = int(kl) if kl is not None else None
    except (TypeError, ValueError):
        kl = None
    inv.observe(s["primitive"], s["algorithm"],
                _occ(m.line, path, owner,
                     s.get("evidence", "site query match"),
                     confidence=float(s.get("confidence", 1.0))),
                params=s.get("params", ""), key_length=kl, mode=s.get("mode", ""))
    return 1


def _emit_call(inv, m, src, path, owner) -> int:
    obj = m.caps.get("obj", "")
    attr = m.caps.get("attr", "")
    q = f"{obj}.{attr}"
    low = q.lower()
    args_node = m.nodes["args"]
    line = m.line
    hits = 0

    # hashlib.md5(...) / hashlib.new("md5")
    for fn, alg in {**HASHLIB_WEAK, **HASHLIB_OK}.items():
        if low.endswith(f"hashlib.{fn}") or (obj == "hashlib" and attr == fn):
            inv.observe("hash", alg, _occ(line, path, owner, f"call to {q}()"))
            hits += 1
    if (obj == "hashlib" and attr == "new") or low.endswith("hashlib.new"):
        for s in _string_args(args_node, src):
            name = s.lower()
            alg = HASHLIB_WEAK.get(name) or HASHLIB_OK.get(name)
            if alg:
                inv.observe("hash", alg, _occ(line, path, owner, f'hashlib.new("{name}")'))
                hits += 1
            break

    # pycryptodome ciphers: DES.new / Crypto.Cipher.AES.new
    last = obj.split(".")[-1]
    if attr == "new" and last in PYCRYPTO_CIPHERS:
        alg, kl = PYCRYPTO_CIPHERS[last]
        mode = ""
        for qa in _arg_qualnames(args_node, src):
            if "MODE_ECB" in qa: mode = "ecb"
            if "MODE_CBC" in qa: mode = "cbc"
            if "MODE_GCM" in qa: mode = "gcm"
        inv.observe("symmetric-cipher", alg,
                    _occ(line, path, owner, f"{q}() call site"),
                    key_length=kl, mode=mode)
        hits += 1

    # cryptography keygens
    if attr == "generate_private_key" and last == "rsa":
        ks = _kw_int(args_node, "key_size", src)
        if ks is not None:
            inv.observe("pk-encryption", "rsa",
                        _occ(line, path, owner, f"RSA keygen key_size={ks}"), key_length=ks)
        else:
            inv.observe("pk-encryption", "rsa",
                        _occ(line, path, owner, "RSA keygen, key_size computed at run time",
                             confidence=0.5, tags=["indeterminate"]))
        hits += 1
    if attr == "generate_private_key" and last == "dsa":
        ks = _kw_int(args_node, "key_size", src) or 1024
        inv.observe("signature", "dsa",
                    _occ(line, path, owner, f"DSA keygen key_size={ks}"), key_length=ks)
        hits += 1
    if attr == "generate_private_key" and last == "ec":
        curve = ""
        for qa in _arg_qualnames(args_node, src):
            tail = qa.split(".")[-1].split("(")[0]
            if tail.upper().startswith("SECP") or "25519" in qa:
                curve = tail.lower()
        inv.observe("signature", "ecdsa",
                    _occ(line, path, owner, f"EC keygen curve={curve or '?'}"), params=curve)
        hits += 1
    # finite-field DH parameter generation: dh.generate_parameters(key_size=N)
    if attr == "generate_parameters" and last == "dh":
        ks = _kw_int(args_node, "key_size", src)
        if ks is not None:
            inv.observe("key-agreement", "dh",
                        _occ(line, path, owner, f"DH parameter generation key_size={ks}"),
                        params="ffdhe", key_length=ks)
        else:
            inv.observe("key-agreement", "dh",
                        _occ(line, path, owner,
                             "DH parameter generation, key_size computed at run time",
                             confidence=0.5, tags=["indeterminate"]),
                        params="ffdhe")
        hits += 1

    return hits


def _emit_attr(inv, m, path, owner) -> int:
    cobj = m.caps.get("cobj", "")
    cattr = m.caps.get("cattr", "")
    if cobj == "ssl" and cattr in SSL_CONST:
        alg, ver = SSL_CONST[cattr]
        inv.observe("protocol", alg,
                    _occ(m.line, path, owner, f"use of ssl.{cattr}"), params=ver)
        return 1
    return 0
