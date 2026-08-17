# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""TLSCollector — read-only endpoint observation, hard-gated by an
operator-signed scope file.

Safety properties (enforced in code, not just documented):
  * refuses to run against any host:port absent from the scope file;
  * verifies an HMAC-SHA256 signature over the scope file before use;
  * performs only standard TLS handshakes (no exploitation, no credential
    testing, no fault injection);
  * bounded connection count and a fixed timeout per probe.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import socket
import ssl

import yaml

from ..model import Inventory, Occurrence
from . import register

TIMEOUT = 5.0


class ScopeError(RuntimeError):
    pass


def load_scope(scope_path: str, key_path: str) -> list[dict]:
    """Validate the signed scope file and return the authorised targets.

    The signature covers everything up to the (single, final) ``signature:``
    line. Any bytes after that line, or a second signature line, invalidate the
    file so that content cannot be smuggled in after signing.
    """
    raw = open(scope_path, "rb").read()
    if raw.count(b"\nsignature:") + (1 if raw.startswith(b"signature:") else 0) != 1 \
            and raw.count(b"signature:") != 1:
        raise ScopeError("scope file must contain exactly one signature line")
    idx = raw.rindex(b"signature:")
    body = raw[:idx]
    tail = raw[idx:]
    # the signature line must be the final line: <hex>\n and nothing after
    m = re.match(rb"signature:\s*([0-9a-fA-F]{64})\s*\Z", tail)
    if not m:
        raise ScopeError("malformed or non-terminal signature line "
                         "(content after the signature is not allowed)")
    sig = m.group(1).decode()
    key = open(key_path, "rb").read().strip()
    expect = hmac.new(key, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        raise ScopeError("scope file signature INVALID — refusing to probe anything")
    doc = yaml.safe_load(body)
    return (doc or {}).get("targets", [])


def sign_scope(scope_path: str, key_path: str) -> str:
    """Helper for operators: (re)compute and append the HMAC signature so that
    it is the single, final line of the file."""
    raw = open(scope_path, "rb").read()
    if b"signature:" in raw:
        raw = raw[: raw.rindex(b"signature:")]
    if raw and not raw.endswith(b"\n"):
        raw += b"\n"
    key = open(key_path, "rb").read().strip()
    sig = hmac.new(key, raw, hashlib.sha256).hexdigest()
    with open(scope_path, "wb") as f:
        f.write(raw + b"signature: " + sig.encode() + b"\n")
    return sig


def _probe_version(host: str, port: int, minimum, maximum) -> dict | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # observation only; we are not authenticating
    ctx.minimum_version = minimum
    ctx.maximum_version = maximum
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return {"version": tls.version(), "cipher": tls.cipher()}
    except (ssl.SSLError, OSError):
        return None


@register("tls")
def run(inv: Inventory, scope_path: str, scope_key: str, **_) -> dict:
    targets = load_scope(scope_path, scope_key)   # raises before any packet if invalid
    probed = findings = 0
    versions = [
        ("1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
        ("1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
        ("1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
        ("1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ]
    for t in targets:
        host, port = t["host"], int(t["port"])
        owner, tags = t.get("owner"), t.get("tags", [])
        probed += 1
        for label, lo, hi in versions:
            res = _probe_version(host, port, lo, hi)
            if not res:
                continue
            findings += 1
            loc = f"{host}:{port}"
            inv.observe("protocol", "tls",
                        Occurrence(collector="tls", locator=loc,
                                   evidence=f"endpoint negotiates TLS {label} "
                                            f"({res['cipher'][0] if res['cipher'] else '?'})",
                                   owner=owner, tags=tags),
                        params=label)
            cipher_name = (res["cipher"][0] or "").upper() if res["cipher"] else ""
            if "ECDHE" in cipher_name or label == "1.3":
                inv.observe("key-agreement", "ecdh",
                            Occurrence(collector="tls", locator=loc,
                                       evidence=f"ECDHE key agreement observed on TLS {label}",
                                       owner=owner, tags=tags))
            if "RSA" in cipher_name:
                inv.observe("signature", "rsa",
                            Occurrence(collector="tls", locator=loc,
                                       evidence=f"RSA authentication in {cipher_name}",
                                       owner=owner, tags=tags, confidence=0.9))
            if "AES_256" in cipher_name or "AES256" in cipher_name:
                inv.observe("symmetric-cipher", "aes",
                            Occurrence(collector="tls", locator=loc,
                                       evidence=f"AES-256 bulk cipher on {loc}",
                                       owner=owner, tags=tags),
                            key_length=256, mode="gcm" if "GCM" in cipher_name else "")
    stats = {"targets": probed, "observations": findings}
    inv.record_collector("tls", stats)
    return stats
