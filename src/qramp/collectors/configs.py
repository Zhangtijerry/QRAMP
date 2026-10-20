# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""ConfigCollector — declarative parsers for common service configurations.

v0.1 covers OpenSSH server config, nginx TLS directives and java.security.
Each parser maps configuration tokens to (primitive, algorithm, params).
"""
from __future__ import annotations

import os
import re

from ..model import Inventory, Occurrence
from . import register

# token -> (primitive, algorithm, params, key_length, mode)
SSH_TOKENS = {
    "3des-cbc": ("symmetric-cipher", "3des", "", 112, "cbc"),
    "aes128-cbc": ("symmetric-cipher", "aes", "", 128, "cbc"),
    "aes256-gcm@openssh.com": ("symmetric-cipher", "aes", "", 256, "gcm"),
    "chacha20-poly1305@openssh.com": ("symmetric-cipher", "chacha20", "", 256, "poly1305"),
    "diffie-hellman-group1-sha1": ("key-agreement", "dh", "group1", 1024, ""),
    "diffie-hellman-group14-sha1": ("key-agreement", "dh", "group14", 2048, ""),
    "diffie-hellman-group14-sha256": ("key-agreement", "dh", "group14", 2048, ""),
    "diffie-hellman-group5-sha1": ("key-agreement", "dh", "group5", 1536, ""),
    "diffie-hellman-group16-sha512": ("key-agreement", "dh", "group16", 4096, ""),
    "diffie-hellman-group-exchange-sha1": ("key-agreement", "dh", "gex-sha1", 1024, ""),
    "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==": ("key-agreement", "dh", "gss-group1", 1024, ""),
    "curve25519-sha256": ("key-agreement", "x25519", "", 256, ""),
    "ecdh-sha2-nistp256": ("key-agreement", "ecdh", "nistp256", 256, ""),
    "sntrup761x25519-sha512@openssh.com": ("key-agreement", "hybrid-pq", "sntrup761+x25519", None, ""),
    "mlkem768x25519-sha256": ("key-agreement", "hybrid-pq", "mlkem768+x25519", None, ""),
    "ssh-rsa": ("signature", "rsa", "ssh-hostkey", 2048, ""),
    "ssh-ed25519": ("signature", "ed25519", "ssh-hostkey", 256, ""),
    "hmac-md5": ("mac", "md5", "hmac", None, ""),
    "hmac-sha1": ("mac", "sha1", "hmac", None, ""),
    "hmac-sha2-256": ("mac", "sha2-256", "hmac", None, ""),
}

NGINX_PROTO = {
    "sslv3": ("protocol", "ssl", "3.0"),
    "tlsv1": ("protocol", "tls", "1.0"),
    "tlsv1.1": ("protocol", "tls", "1.1"),
    "tlsv1.2": ("protocol", "tls", "1.2"),
    "tlsv1.3": ("protocol", "tls", "1.3"),
}


@register("configs")
def run(inv: Inventory, config_dir: str, owner_map: dict | None = None, **_) -> dict:
    owner_map = owner_map or {}
    if not os.path.isdir(config_dir):
        raise ValueError(f"configuration directory does not exist: {config_dir}")
    scanned_paths, errors = [], []
    n = 0
    for root, _d, files in os.walk(config_dir, onerror=lambda e: errors.append(str(e))):
        for fn in files:
            path = os.path.join(root, fn)
            owner = owner_map.get(fn)
            low = fn.lower()
            if not ("sshd_config" in low or low.endswith(".conf") or "java.security" in low):
                continue
            try:
                text = open(path, encoding="utf-8").read()
            except (OSError, UnicodeError) as exc:
                errors.append(str(exc))
                continue
            scanned_paths.append(os.path.abspath(path))
            if "sshd_config" in low:
                n += _parse_sshd(inv, path, text, owner)
            elif low.endswith((".conf",)) and ("ssl_" in text or "server {" in text):
                n += _parse_nginx(inv, path, text, owner)
            elif "java.security" in low:
                n += _parse_java_security(inv, path, text, owner)
    stats = {"findings": n, "root": os.path.abspath(config_dir),
             "scanned_paths": sorted(scanned_paths), "errors": errors}
    inv.record_collector("configs", stats)
    return stats


def _parse_sshd(inv: Inventory, path: str, text: str, owner: str | None) -> int:
    n = 0
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"(?i)^(Ciphers|KexAlgorithms|MACs|HostKeyAlgorithms)\s+(.+)$", s)
        if not m:
            continue
        for tok in re.split(r"[,\s]+", m.group(2).strip()):
            tok = tok.lstrip("+-^").lower()
            if tok in SSH_TOKENS:
                prim, alg, params, kl, mode = SSH_TOKENS[tok]
                inv.observe(prim, alg,
                            Occurrence(collector="configs", locator=f"{path}:{i}",
                                       evidence=f"{m.group(1)} includes {tok}", owner=owner),
                            params=params, key_length=kl, mode=mode)
                n += 1
    return n


def _parse_nginx(inv: Inventory, path: str, text: str, owner: str | None) -> int:
    n = 0
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip().rstrip(";")
        if s.lower().startswith("ssl_protocols"):
            for tok in s.split()[1:]:
                t = tok.lower()
                if t in NGINX_PROTO:
                    prim, alg, ver = NGINX_PROTO[t]
                    inv.observe(prim, alg,
                                Occurrence(collector="configs", locator=f"{path}:{i}",
                                           evidence=f"ssl_protocols enables {tok}", owner=owner,
                                           tags=["external"] if "listen 443" in text else []),
                                params=ver)
                    n += 1
        if s.lower().startswith("ssl_ciphers"):
            low = s.lower()
            ext = ["external"] if "listen 443" in text else []
            if "rc4" in low or "3des" in low:
                alg = "rc4" if "rc4" in low else "3des"
                inv.observe("symmetric-cipher", alg,
                            Occurrence(collector="configs", locator=f"{path}:{i}",
                                       evidence="legacy cipher in ssl_ciphers",
                                       owner=owner, tags=ext))
                n += 1
            # static-RSA key exchange: OpenSSL "kRSA" token, or an explicit
            # RSA key-transport suite name (AES...-SHA without ECDHE/DHE).
            if _has_static_rsa_kx(low):
                inv.observe("key-agreement", "rsa",
                            Occurrence(collector="configs", locator=f"{path}:{i}",
                                       evidence="static-RSA key exchange in ssl_ciphers "
                                                "(no forward secrecy)",
                                       owner=owner, tags=ext))
                n += 1
            # DHE (ephemeral finite-field DH) key exchange. The strength depends
            # on the dhparam file elsewhere in the config; recorded here without
            # a key length and reconciled by entity resolution with any
            # ssl_dhparam finding.
            if "dhe" in low and "ecdhe" not in low.replace("ecdhe", " ecdhe "):
                inv.observe("key-agreement", "dh",
                            Occurrence(collector="configs", locator=f"{path}:{i}",
                                       evidence="DHE (finite-field) key exchange in ssl_ciphers",
                                       owner=owner, confidence=0.8, tags=ext))
                n += 1
        # ssl_dhparam <file>: strength is the prime bit length. A small (<=1024,
        # or export-grade 512) group is a classical (Logjam) break, not just a
        # future quantum one.
        if s.lower().startswith("ssl_dhparam"):
            ext = ["external"] if "listen 443" in text else []
            bits = _dhparam_bits(s, os.path.dirname(path))
            inv.observe("key-agreement", "dh",
                        Occurrence(collector="configs", locator=f"{path}:{i}",
                                   evidence=(f"ssl_dhparam group of {bits} bits"
                                             if bits else "ssl_dhparam (size undetermined)"),
                                   confidence=1.0 if bits else 0.5,
                                   owner=owner,
                                   tags=(ext + (["indeterminate"] if not bits else []))),
                        params="ffdhe", key_length=bits)
            n += 1
    return n


def _dhparam_bits(directive: str, base_dir: str) -> int | None:
    """Resolve the prime bit length of an ssl_dhparam file. Reads the referenced
    PEM if present; falls back to a size hinted in the filename (e.g.
    dhparam2048.pem, dh-1024.pem)."""
    import re as _re
    parts = directive.split()
    fname = parts[1].strip('"; ') if len(parts) > 1 else ""
    # try to read the actual file
    for cand in (fname, os.path.join(base_dir, os.path.basename(fname))):
        if cand and os.path.exists(cand):
            bits = _pem_dh_bits(cand)
            if bits:
                return bits
    m = _re.search(r"(512|768|1024|1536|2048|3072|4096)", fname)
    return int(m.group(1)) if m else None


def _pem_dh_bits(path: str) -> int | None:
    try:
        data = open(path, "rb").read()
        from cryptography.hazmat.primitives.serialization import load_pem_parameters
        params = load_pem_parameters(data)
        return params.parameter_numbers().p.bit_length()
    except Exception:
        return None


def _has_static_rsa_kx(cipherline: str) -> bool:
    """Heuristic: does an OpenSSL cipher string enable static-RSA key exchange?
    True if the explicit kRSA/aRSA-only token appears, or an RSA key-transport
    suite name is listed without a forward-secret (ECDHE/DHE) prefix."""
    low = cipherline.lower()
    if "krsa" in low:
        return True
    # suite names like AES256-SHA / DES-CBC3-SHA are static-RSA; ECDHE-/DHE- are not
    for tok in low.replace(":", " ").split():
        if tok.startswith(("aes", "des", "camellia", "seed", "rc4")) \
                and "ecdhe" not in tok and "dhe" not in tok \
                and not tok.startswith("tls_"):
            return True
    return False


def _parse_java_security(inv: Inventory, path: str, text: str, owner: str | None) -> int:
    n = 0
    m = re.search(r"jdk\.tls\.disabledAlgorithms\s*=\s*(.+)", text)
    if m:
        disabled = m.group(1).lower()
        for weak in ("sslv3", "tlsv1", "rc4", "md5", "3des"):
            if weak not in disabled:
                prim, alg = ("protocol", "tls") if weak.startswith(("ssl", "tls")) else \
                            ("symmetric-cipher", weak) if weak in ("rc4", "3des") else ("hash", weak)
                params = {"sslv3": "3.0", "tlsv1": "1.0"}.get(weak, "")
                inv.observe(prim, alg,
                            Occurrence(collector="configs", locator=path,
                                       evidence=f"{weak} NOT in jdk.tls.disabledAlgorithms",
                                       confidence=0.6, owner=owner),
                            params=params)
                n += 1
    return n
