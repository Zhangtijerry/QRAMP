# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""SourceCollector (C / C++) — interprets matches from a declarative ``.scm``
query file (``queries/c.scm``) into CryptoAssets.

C crypto idioms differ from the scoped-call languages: there is no ``Type::method``
receiver. The algorithm is encoded in the function name itself
(``EVP_md5()``, ``EVP_aes_256_gcm()``), passed as a string
(``EVP_get_cipherbyname("des-cbc")``) or an integer
(``RSA_generate_key(2048, ...)``). This interpreter therefore keys on the
function name and, where needed, its literal arguments — covering OpenSSL's EVP
and legacy APIs plus libsodium.
"""
from __future__ import annotations

import os
import re

from ..model import Inventory, Occurrence
from . import register
from .tsquery import QueryEngine, get_engine

_ENGINE = QueryEngine("c")
HAVE_TS_C = _ENGINE.available

C_EXTS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")

# 1) OpenSSL EVP_<alg>() constructors: the algorithm is the function name.
#    name -> (primitive, algorithm, key_length, mode)
EVP_FUNCS = {
    "EVP_md5": ("hash", "md5", None, ""),
    "EVP_md4": ("hash", "md4", None, ""),
    "EVP_sha1": ("hash", "sha1", None, ""),
    "EVP_sha224": ("hash", "sha2-224", None, ""),
    "EVP_sha256": ("hash", "sha2-256", None, ""),
    "EVP_sha384": ("hash", "sha2-384", None, ""),
    "EVP_sha512": ("hash", "sha2-512", None, ""),
    "EVP_sha3_256": ("hash", "sha3-256", None, ""),
    "EVP_sha3_512": ("hash", "sha3-512", None, ""),
    "EVP_des_ecb": ("symmetric-cipher", "des", 56, "ecb"),
    "EVP_des_cbc": ("symmetric-cipher", "des", 56, "cbc"),
    "EVP_des_ede3_cbc": ("symmetric-cipher", "3des", 112, "cbc"),
    "EVP_des_ede3": ("symmetric-cipher", "3des", 112, ""),
    "EVP_rc4": ("symmetric-cipher", "rc4", 128, ""),
    "EVP_rc2_cbc": ("symmetric-cipher", "rc2", None, "cbc"),
    "EVP_bf_cbc": ("symmetric-cipher", "blowfish", None, "cbc"),
    "EVP_aes_128_cbc": ("symmetric-cipher", "aes", 128, "cbc"),
    "EVP_aes_192_cbc": ("symmetric-cipher", "aes", 192, "cbc"),
    "EVP_aes_256_cbc": ("symmetric-cipher", "aes", 256, "cbc"),
    "EVP_aes_128_gcm": ("symmetric-cipher", "aes", 128, "gcm"),
    "EVP_aes_256_gcm": ("symmetric-cipher", "aes", 256, "gcm"),
    "EVP_chacha20_poly1305": ("symmetric-cipher", "chacha20", 256, "poly1305"),
}

# 2) direct legacy/one-shot functions: name -> (primitive, algorithm, kl, mode,
#    key_arg_index or None)
DIRECT_FUNCS = {
    "MD5": ("hash", "md5", None, "", None),
    "MD4": ("hash", "md4", None, "", None),
    "SHA1": ("hash", "sha1", None, "", None),
    "SHA224": ("hash", "sha2-224", None, "", None),
    "SHA256": ("hash", "sha2-256", None, "", None),
    "SHA512": ("hash", "sha2-512", None, "", None),
    "RSA_generate_key": ("pk-encryption", "rsa", None, "", 0),      # RSA_generate_key(bits,...)
    "RSA_generate_key_ex": ("pk-encryption", "rsa", None, "", 1),   # RSA_generate_key_ex(rsa,bits,...)
    "DSA_generate_parameters": ("signature", "dsa", None, "", 0),
    "DSA_generate_parameters_ex": ("signature", "dsa", None, "", 1),
    "DH_generate_parameters": ("key-agreement", "dh", None, "ffdhe", 0),
    "DH_generate_parameters_ex": ("key-agreement", "dh", None, "ffdhe", 1),
    "EC_KEY_new_by_curve_name": ("signature", "ecdsa", None, "", None),
}

# 3) functions whose first STRING argument names the algorithm.
STRING_ARG_FUNCS = {
    "EVP_get_cipherbyname", "EVP_get_digestbyname", "EVP_CIPHER_fetch",
    "EVP_MD_fetch",
}

# cipher/digest names as they appear in OpenSSL by-name lookups.
BYNAME_MAP = {
    "des-cbc": ("symmetric-cipher", "des", 56, "cbc"),
    "des-ecb": ("symmetric-cipher", "des", 56, "ecb"),
    "des-ede3-cbc": ("symmetric-cipher", "3des", 112, "cbc"),
    "rc4": ("symmetric-cipher", "rc4", 128, ""),
    "bf-cbc": ("symmetric-cipher", "blowfish", None, "cbc"),
    "aes-128-cbc": ("symmetric-cipher", "aes", 128, "cbc"),
    "aes-256-gcm": ("symmetric-cipher", "aes", 256, "gcm"),
    "md5": ("hash", "md5", None, ""),
    "sha1": ("hash", "sha1", None, ""),
    "sha256": ("hash", "sha2-256", None, ""),
}

# 4) libsodium: modern primitives, generally PQ-transitional-safe symmetric.
SODIUM_FUNCS = {
    "crypto_secretbox_easy": ("symmetric-cipher", "xsalsa20", 256, "poly1305"),
    "crypto_aead_chacha20poly1305_encrypt": ("symmetric-cipher", "chacha20", 256, "poly1305"),
    "crypto_aead_aes256gcm_encrypt": ("symmetric-cipher", "aes", 256, "gcm"),
    "crypto_hash_sha256": ("hash", "sha2-256", None, ""),
    "crypto_hash_sha512": ("hash", "sha2-512", None, ""),
    "crypto_sign_ed25519": ("signature", "ed25519", 256, ""),
    "crypto_box_curve25519xsalsa20poly1305": ("key-agreement", "x25519", 256, ""),
}


def _number_arg(args_node, index, src):
    positional = [c for c in args_node.children
                  if c.type not in ("(", ")", ",")]
    if index < len(positional) and positional[index].type == "number_literal":
        raw = src[positional[index].start_byte:positional[index].end_byte].decode()
        m = re.match(r"(\d[\d']*)", raw)     # allow C++14 digit separators
        if m:
            try:
                return int(m.group(1).replace("'", ""))
            except ValueError:
                return None
    return None


def _first_string_arg(args_node, src):
    for c in args_node.children:
        if c.type == "string_literal":
            for sc in c.children:
                if sc.type == "string_content":
                    return src[sc.start_byte:sc.end_byte].decode("utf-8", "replace")
            # fallback: strip the quotes
            raw = src[c.start_byte:c.end_byte].decode("utf-8", "replace")
            return raw.strip('"')
    return None


@register("source-c")
def run(inv: Inventory, source_dir: str, owner_map: dict | None = None,
        query_dir: str | None = None, **_) -> dict:
    owner_map = owner_map or {}
    engine = get_engine("c", query_dir) if query_dir else _ENGINE
    if not engine.available:
        stats = {"files": 0, "call_sites": 0, "skipped": engine.reason}
        inv.record_collector("source-c", stats)
        return stats

    if not os.path.isdir(source_dir):
        raise ValueError(f"source directory does not exist: {source_dir}")
    scanned_paths, errors = [], []
    files = hits = 0
    for root, _d, fns in os.walk(source_dir, onerror=lambda e: errors.append(str(e))):
        if any(p in root for p in (".git", "build", "node_modules", "cmake-build")):
            continue
        for fn in fns:
            if not fn.endswith(C_EXTS):
                continue
            path = os.path.join(root, fn)
            src = open(path, "rb").read()
            scanned_paths.append(os.path.abspath(path))
            if engine.syntax_errors(src):
                errors.append(f"parse errors: {os.path.abspath(path)}")
            files += 1
            hits += _interpret(inv, src, path, owner_map.get(fn), engine)
    stats = {"files": files, "call_sites": hits,
             "root": os.path.abspath(source_dir),
             "scanned_paths": sorted(scanned_paths), "errors": errors,
             "query_hash": engine.query_source_hash(),
             "query_sources": engine.describe_sources()}
    inv.record_collector("source-c", stats)
    return stats


def _occ(line, path, owner, evidence, confidence=1.0, tags=None):
    return Occurrence(collector="source-c", locator=f"{path}:{line}",
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
    return hits


def _emit_call(inv, m, src, path, owner) -> int:
    fn = m.caps.get("fn", "")
    line = m.line
    args = m.nodes.get("args")

    # 1) EVP_<alg>() name-encoded constructors
    if fn in EVP_FUNCS:
        prim, alg, kl, mode = EVP_FUNCS[fn]
        inv.observe(prim, alg, _occ(line, path, owner, f"{fn}() call site"),
                    key_length=kl, mode=mode)
        return 1

    # 2) direct legacy/one-shot functions (optionally with a key-size arg)
    if fn in DIRECT_FUNCS:
        prim, alg, kl_default, mode, key_idx = DIRECT_FUNCS[fn]
        key_length = kl_default
        if key_idx is not None and args is not None:
            n = _number_arg(args, key_idx, src)
            if n is not None:
                key_length = n
            elif prim in ("pk-encryption", "key-agreement", "signature"):
                inv.observe(prim, alg,
                            _occ(line, path, owner,
                                 f"{alg} key size computed at run time",
                                 confidence=0.5, tags=["indeterminate"]),
                            params=mode)
                return 1
        inv.observe(prim, alg,
                    _occ(line, path, owner, f"{fn}(...)"
                         + (f", key size {key_length}" if key_length else "")),
                    params=mode if prim == "key-agreement" else "",
                    key_length=key_length,
                    mode=mode if prim == "symmetric-cipher" else "")
        return 1

    # 3) by-name lookups: first string arg names the algorithm
    if fn in STRING_ARG_FUNCS and args is not None:
        name = (_first_string_arg(args, src) or "").lower()
        mapped = BYNAME_MAP.get(name)
        if mapped:
            prim, alg, kl, mode = mapped
            inv.observe(prim, alg,
                        _occ(line, path, owner, f'{fn}("{name}")'),
                        key_length=kl, mode=mode)
            return 1
        if name:
            inv.observe("symmetric-cipher", name.replace("-", ""),
                        _occ(line, path, owner, f'{fn}("{name}") (unmapped)',
                             confidence=0.5, tags=["indeterminate"]))
            return 1
        return 0

    # 4) libsodium primitives
    if fn in SODIUM_FUNCS:
        prim, alg, kl, mode = SODIUM_FUNCS[fn]
        inv.observe(prim, alg, _occ(line, path, owner, f"{fn}() call site"),
                    key_length=kl, mode=mode)
        return 1

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
