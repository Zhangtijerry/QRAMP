# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""SourceCollector (Java) — interprets matches from a declarative ``.scm``
query file (``queries/java.scm``) into CryptoAssets.

The *structural* detection ("which AST shapes are crypto call sites") now lives
in the versioned query file. This module keeps only the *semantic* mapping:
turning a JCA transformation string and an associated key size into a
normalised asset. The enclosing-method association for key sizes (which a flat
query cannot express) is resolved here by node containment.
"""
from __future__ import annotations

import os

from ..model import Inventory, Occurrence
from . import register
from .tsquery import QueryEngine, get_engine

_ENGINE = QueryEngine("java")
HAVE_TS_JAVA = _ENGINE.available

FACTORY_PRIMITIVE = {
    "MessageDigest": "hash",
    "Cipher": "symmetric-cipher",
    "KeyPairGenerator": "pk-encryption",
    "KeyGenerator": "symmetric-cipher",
    "KeyAgreement": "key-agreement",
    "Signature": "signature",
    "Mac": "mac",
    "SSLContext": "protocol",
    "SecureRandom": "random",
}

ALG_MAP = {
    "md5": ("hash", "md5", None), "md2": ("hash", "md2", None),
    "sha-1": ("hash", "sha1", None), "sha1": ("hash", "sha1", None),
    "sha-256": ("hash", "sha2-256", None), "sha-384": ("hash", "sha2-384", None),
    "sha-512": ("hash", "sha2-512", None),
    "sha3-256": ("hash", "sha3-256", None), "sha3-512": ("hash", "sha3-512", None),
    "des": ("symmetric-cipher", "des", 56),
    "desede": ("symmetric-cipher", "3des", 112), "tripledes": ("symmetric-cipher", "3des", 112),
    "rc4": ("symmetric-cipher", "rc4", 128), "arcfour": ("symmetric-cipher", "rc4", 128),
    "blowfish": ("symmetric-cipher", "blowfish", None),
    "aes": ("symmetric-cipher", "aes", None),
    "chacha20": ("symmetric-cipher", "chacha20", 256),
    "rsa": ("pk-encryption", "rsa", None),
    "ec": ("signature", "ecdsa", None), "ecdsa": ("signature", "ecdsa", None),
    "dsa": ("signature", "dsa", None),
    "dh": ("key-agreement", "dh", None), "diffiehellman": ("key-agreement", "dh", None),
    "ecdh": ("key-agreement", "ecdh", None),
    "ml-kem": ("key-agreement", "ml-kem", None), "kyber": ("key-agreement", "ml-kem", None),
    "ml-dsa": ("signature", "ml-dsa", None), "dilithium": ("signature", "ml-dsa", None),
}

SIG_WITH = {"rsa": ("signature", "rsa"), "dsa": ("signature", "dsa"),
            "ecdsa": ("signature", "ecdsa")}

PROTO_MAP = {
    "sslv3": ("ssl", "3.0"), "sslv2": ("ssl", "2.0"),
    "tls": ("tls", ""), "tlsv1": ("tls", "1.0"), "tlsv1.1": ("tls", "1.1"),
    "tlsv1.2": ("tls", "1.2"), "tlsv1.3": ("tls", "1.3"),
}


def _enclosing_method_range(node):
    n = node.parent
    while n is not None:
        if n.type == "method_declaration":
            return (n.start_byte, n.end_byte)
        n = n.parent
    return None


def _parse_transformation(spec: str):
    parts = spec.split("/")
    head = parts[0].strip().lower()
    mode = parts[1].strip().lower() if len(parts) > 1 else ""
    mapped = ALG_MAP.get(head)
    if mapped is None:
        return None
    primitive, algorithm, key_length = mapped
    return primitive, algorithm, key_length, mode


@register("source-java")
def run(inv: Inventory, source_dir: str, owner_map: dict | None = None,
        query_dir: str | None = None, **_) -> dict:
    owner_map = owner_map or {}
    engine = get_engine("java", query_dir) if query_dir else _ENGINE
    if not engine.available:
        stats = {"files": 0, "call_sites": 0, "skipped": engine.reason}
        inv.record_collector("source-java", stats)
        return stats

    files = hits = 0
    for root, _d, fns in os.walk(source_dir):
        if any(p in root for p in (".git", "target", "build", "node_modules")):
            continue
        for fn in fns:
            if not fn.endswith(".java"):
                continue
            path = os.path.join(root, fn)
            src = open(path, "rb").read()
            files += 1
            hits += _interpret(inv, src, path, owner_map.get(fn), engine)
    stats = {"files": files, "call_sites": hits,
             "query_hash": engine.query_source_hash(),
             "query_sources": engine.describe_sources()}
    inv.record_collector("source-java", stats)
    return stats


def _interpret(inv, src, path, owner, engine=None) -> int:
    engine = engine or _ENGINE
    getsites = []
    keysizes = []            # (method_range, size)
    site_hits = 0
    for m in engine.run(src):
        if m.settings.get("primitive") and m.settings.get("algorithm"):
            site_hits += _emit_site(inv, m, path, owner)
            continue
        if "spec" in m.caps:
            getsites.append(m)
        if "keysize" in m.caps:
            rng = _enclosing_method_range(m.nodes["keysize"])
            try:
                keysizes.append((rng, int(m.caps["keysize"].rstrip("Ll"))))
            except ValueError:
                pass

    def keysize_for(site_node):
        rng = _enclosing_method_range(site_node)
        if rng is None:
            return None
        for r, size in keysizes:
            if r == rng:
                return size
        return None

    hits = site_hits
    for m in getsites:
        recv = m.caps.get("recv", "").split(".")[-1]
        spec = m.caps["spec"]
        ks = keysize_for(m.nodes["site"])
        hits += _emit(inv, m.line, recv, spec, ks, path, owner)
    return hits


def _occ(line, path, owner, evidence, confidence=1.0, tags=None):
    return Occurrence(collector="source-java", locator=f"{path}:{line}",
                      evidence=evidence, confidence=confidence,
                      owner=owner, tags=tags or [])


def _emit(inv, line, receiver, spec, keysize, path, owner) -> int:
    low = spec.strip().lower()

    if receiver == "SSLContext" or low.startswith(("tls", "ssl")):
        proto = PROTO_MAP.get(low)
        if proto:
            alg, ver = proto
            inv.observe("protocol", alg,
                        _occ(line, path, owner, f'SSLContext.getInstance("{spec}")'),
                        params=ver)
            return 1

    if "with" in low:
        tail = low.rsplit("with", 1)[-1]
        sig = SIG_WITH.get(tail)
        if sig:
            prim, alg = sig
            inv.observe(prim, alg,
                        _occ(line, path, owner, f'Signature.getInstance("{spec}")', 0.9))
            head = low.split("with", 1)[0]
            if head in ("md5", "sha1", "sha-1", "md2"):
                inv.observe("hash", "sha1" if "sha" in head else head.replace("-", ""),
                            _occ(line, path, owner, f"weak digest in signature {spec}", 0.9))
            return 1

    if low.startswith("hmac"):
        h = low[4:]
        digest = {"md5": "md5", "sha1": "sha1", "sha256": "sha2-256",
                  "sha512": "sha2-512"}.get(h)
        if digest:
            inv.observe("mac", digest,
                        _occ(line, path, owner, f'Mac.getInstance("{spec}")'), params="hmac")
            return 1

    parsed = _parse_transformation(spec)
    if parsed is None:
        prim = FACTORY_PRIMITIVE.get(receiver, "protocol")
        inv.observe(prim, low.split("/")[0].replace("-", ""),
                    _occ(line, path, owner, f'{receiver}.getInstance("{spec}")', 0.6))
        return 1

    primitive, algorithm, kl_default, mode = parsed
    key_length = keysize if keysize is not None else kl_default
    if receiver == "KeyPairGenerator" and algorithm == "rsa":
        primitive = "pk-encryption"
    if receiver == "KeyGenerator" and algorithm in ("aes", "des", "3des", "chacha20"):
        primitive = "symmetric-cipher"
    inv.observe(primitive, algorithm,
                _occ(line, path, owner, f'{receiver}.getInstance("{spec}")'
                     + (f", key size {key_length}" if key_length else "")),
                key_length=key_length, mode=mode)
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
