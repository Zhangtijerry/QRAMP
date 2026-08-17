# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.handshake — active verification of post-quantum hybrid key exchange.

The passive TLSCollector records which groups an endpoint *offers*. This module
goes one step further for the ``enable-hybrid-kex`` acceptance check: it
actively attempts a real TLS handshake that forces a post-quantum hybrid group
and measures the success rate over several attempts.

It is capability-tiered and never lies:

  * If the local TLS stack can force PQ groups (OpenSSL >= 3.5 with a Python
    ``ssl`` that exposes ``set_groups``, or an equivalent), it performs N real
    handshakes pinned to the requested PQ group and reports the negotiated
    group plus the success rate.
  * If it cannot (older OpenSSL, no ``set_groups``), it reports
    ``capability = "unavailable"`` with the specific reason, and the verifier
    treats the acceptance predicate as *deferred* (fail-closed) rather than
    falsely passing.

Safety: like the TLS collector, this probe is read-only (a standard handshake,
no application data, no exploitation) and runs only against hosts named in an
operator-signed scope file.
"""
from __future__ import annotations

import re
import socket
import ssl
import time

# Group names understood as post-quantum hybrids across stacks/spellings.
PQ_HYBRID_GROUPS = (
    "X25519MLKEM768",          # OpenSSL 3.5+, RFC name
    "x25519_kyber768",         # oqs-provider / draft spelling
    "SecP256r1MLKEM768",
    "p256_kyber768",
    "mlkem768x25519-sha256",   # SSH-style, accepted defensively
)

DEFAULT_ATTEMPTS = 5
TIMEOUT = 5.0


def openssl_version_tuple() -> tuple[int, int, int]:
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", ssl.OPENSSL_VERSION)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def local_capability() -> dict:
    """Describe what the local TLS stack can do for PQ hybrid handshakes."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    has_set_groups = hasattr(ctx, "set_groups")
    ver = openssl_version_tuple()
    # OpenSSL 3.5 ships X25519MLKEM768 as a default group; earlier versions
    # need an external provider (oqs-provider) which, if present, still needs
    # set_groups to select it from Python.
    pq_capable = has_set_groups and ver >= (3, 5, 0)
    reason = None
    if not has_set_groups:
        reason = "python ssl lacks SSLContext.set_groups (needs Python built against OpenSSL 3.5+)"
    elif ver < (3, 5, 0):
        reason = (f"OpenSSL {'.'.join(map(str, ver))} has no PQ hybrid groups "
                  f"(needs 3.5+ or oqs-provider)")
    return {"openssl": ssl.OPENSSL_VERSION, "openssl_tuple": list(ver),
            "has_set_groups": has_set_groups, "pq_capable": pq_capable,
            "reason": reason}


def _try_group(host: str, port: int, group: str) -> tuple[bool, str | None, str | None]:
    """One handshake pinned to `group`. Returns (ok, negotiated_group, error)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # observation only; not authenticating
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        ctx.set_groups(group)                # raises if the name is unknown to the stack
    except Exception as e:                    # pragma: no cover - stack-dependent
        return False, None, f"set_groups({group}) failed: {e}"
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                negotiated = None
                # Python 3.13+ exposes group(); fall back to cipher tuple otherwise
                if hasattr(tls, "group"):
                    try:
                        negotiated = tls.group()
                    except Exception:
                        negotiated = None
                return True, negotiated or group, None
    except (ssl.SSLError, OSError) as e:
        return False, None, str(e)


def probe_pq_hybrid(host: str, port: int, attempts: int = DEFAULT_ATTEMPTS,
                    groups: tuple = PQ_HYBRID_GROUPS) -> dict:
    """Actively verify PQ hybrid key exchange at host:port.

    Returns a structured result with a machine-usable ``verdict``:
      * 'pass'      — handshakes succeeded on a PQ group above the threshold;
      * 'fail'      — the stack is capable but the endpoint would not negotiate
                      a PQ group (or success rate below threshold);
      * 'deferred'  — the local stack cannot force PQ groups, so the check
                      cannot be performed here (fail-closed, not a pass).
    """
    cap = local_capability()
    result = {"host": host, "port": port, "attempts": attempts,
              "capability": cap, "negotiated_group": None,
              "successes": 0, "success_rate": 0.0, "errors": [],
              "verdict": "deferred"}

    if not cap["pq_capable"]:
        result["verdict"] = "deferred"
        result["errors"].append(cap["reason"])
        return result

    # try each candidate group name until one is accepted by the local stack
    chosen = None
    for g in groups:
        ok, negotiated, err = _try_group(host, port, g)
        if err and "set_groups" in err:
            continue                         # this spelling unknown; try next
        chosen = g
        successes = 1 if ok else 0
        if ok:
            result["negotiated_group"] = negotiated
        errs = [] if ok else [err]
        # remaining attempts on the accepted group
        for _ in range(attempts - 1):
            ok2, neg2, err2 = _try_group(host, port, g)
            successes += 1 if ok2 else 0
            if ok2 and not result["negotiated_group"]:
                result["negotiated_group"] = neg2
            if not ok2 and err2:
                errs.append(err2)
        result["successes"] = successes
        result["success_rate"] = round(successes / attempts, 3)
        result["errors"] = errs[:3]
        break

    if chosen is None:
        # local stack knows none of the candidate group names
        result["verdict"] = "deferred"
        result["errors"].append("no known PQ hybrid group name accepted by local stack")
        return result

    result["verdict"] = "pass" if result["success_rate"] >= 0.999 else "fail"
    return result


# --- Shor-broken parameter probes for decommission-legacy -------------------

# Legacy protocol versions a decommissioned endpoint must refuse.
LEGACY_VERSIONS = (
    ("SSLv3", ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else None),
    ("TLS1.0", ssl.TLSVersion.TLSv1),
    ("TLS1.1", ssl.TLSVersion.TLSv1_1),
)

# Cipher-selection strings for Shor-relevant / broken key exchange and bulk
# ciphers. A decommissioned endpoint must NOT complete a handshake with any of
# them. Names are OpenSSL cipher-list tokens; ones the local stack cannot even
# offer are skipped (reported as not-probeable rather than pass).
SHOR_BROKEN_CIPHERS = (
    ("static-RSA-kx", "kRSA"),      # RSA key transport: no forward secrecy, Shor-broken
    ("3DES", "3DES"),
    ("RC4", "RC4"),
    ("DES", "DES"),
    ("EXPORT", "EXPORT"),
    ("export-DHE", "EXP+kEDH"),     # export-grade (<=512-bit) ephemeral DH: Logjam
    ("weak-DHE-DES", "DHE-RSA-DES-CBC-SHA"),
)


def _probe_version_refused(host: str, port: int, version) -> tuple[str, str]:
    """Attempt a handshake pinned to a legacy version.
    Returns (outcome, detail): outcome in {'refused','accepted','error'}."""
    if version is None:
        return "unprobeable", "version not available in local stack"
    import warnings
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            # pinning a deprecated legacy version is deliberate here
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, OSError) as e:
        return "unprobeable", f"cannot pin version: {e}"
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return "accepted", f"negotiated {tls.version()}"
    except (ssl.SSLError, OSError) as e:
        return "refused", str(e)[:60]


def _probe_cipher_refused(host: str, port: int, selector: str) -> tuple[str, str]:
    """Attempt a handshake forcing a Shor-broken cipher selector (TLS<=1.2)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2   # these kx/ciphers only exist <=1.2
    try:
        ctx.set_ciphers(selector)
    except ssl.SSLError:
        # local OpenSSL cannot even offer this cipher -> we cannot probe it here
        return "unprobeable", f"local stack cannot offer {selector}"
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                c = tls.cipher()
                return "accepted", f"negotiated {c[0] if c else '?'}"
    except (ssl.SSLError, OSError) as e:
        return "refused", str(e)[:60]


def probe_decommissioned(host: str, port: int) -> dict:
    """Actively confirm an endpoint no longer negotiates any Shor-broken or
    legacy parameter.

    Verdict:
      * 'pass'      — every probeable legacy version and Shor-broken cipher was
                      REFUSED, and at least one probe could actually be run;
      * 'fail'      — the endpoint ACCEPTED at least one legacy/Shor-broken
                      parameter (it is not decommissioned);
      * 'deferred'  — nothing could be probed here (e.g. endpoint unreachable,
                      or the local stack can offer none of the challenges) —
                      fail-closed, not a pass.
    """
    result = {"host": host, "port": port,
              "accepted": [], "refused": [], "unprobeable": [],
              "verdict": "deferred", "errors": []}

    def record(label, outcome, detail):
        if outcome == "accepted":
            result["accepted"].append({"probe": label, "detail": detail})
        elif outcome == "refused":
            result["refused"].append({"probe": label, "detail": detail})
        else:
            result["unprobeable"].append({"probe": label, "detail": detail})

    # reachability check first
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            pass
    except OSError as e:
        result["errors"].append(f"endpoint unreachable: {e}")
        result["verdict"] = "deferred"
        return result

    for label, ver in LEGACY_VERSIONS:
        outcome, detail = _probe_version_refused(host, port, ver)
        record(label, outcome, detail)
    for label, selector in SHOR_BROKEN_CIPHERS:
        outcome, detail = _probe_cipher_refused(host, port, selector)
        record(label, outcome, detail)

    probeable = len(result["accepted"]) + len(result["refused"])
    if result["accepted"]:
        result["verdict"] = "fail"
    elif probeable == 0:
        # we could not actually test anything -> cannot confirm
        result["verdict"] = "deferred"
        result["errors"].append("no legacy/Shor-broken parameter was probeable "
                                "on the local stack")
    else:
        result["verdict"] = "pass"
    return result
