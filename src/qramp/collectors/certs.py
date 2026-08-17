# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""CertCollector — parses X.509 material (PEM/DER), public parts only.

Extracts, per certificate:
  * the subject public-key algorithm and size (weak RSA / weak curve flagged);
  * the certificate's own SIGNATURE algorithm as a composite signature asset
    (e.g. SHA1-with-RSA), so a certificate signed with a broken digest is
    caught as a weak *signing* operation, not merely "SHA1 exists somewhere";
  * the validity window (expired / expiring-soon tags).

Never reads private keys.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

from ..model import Inventory, Occurrence, Certificate
from . import register

EXTS = {".pem", ".crt", ".cer", ".der"}

# minimum acceptable RSA modulus / DH group size (bits)
RSA_MIN_BITS = 2048
# EC curves considered too small for current use
WEAK_CURVES = {"secp192r1", "prime192v1", "secp160r1", "secp224r1", "prime239v1"}

# signature-algorithm OID name -> (signature algorithm, hash algorithm)
# hash None means the scheme has its own (e.g. Ed25519).
SIG_ALG = {
    "md5WithRSAEncryption": ("rsa", "md5"),
    "sha1WithRSAEncryption": ("rsa", "sha1"),
    "sha224WithRSAEncryption": ("rsa", "sha2-224"),
    "sha256WithRSAEncryption": ("rsa", "sha2-256"),
    "sha384WithRSAEncryption": ("rsa", "sha2-384"),
    "sha512WithRSAEncryption": ("rsa", "sha2-512"),
    "rsassaPss": ("rsa", "pss"),
    "dsa-with-sha1": ("dsa", "sha1"),
    "dsa-with-sha256": ("dsa", "sha2-256"),
    "ecdsa-with-SHA1": ("ecdsa", "sha1"),
    "ecdsa-with-SHA224": ("ecdsa", "sha2-224"),
    "ecdsa-with-SHA256": ("ecdsa", "sha2-256"),
    "ecdsa-with-SHA384": ("ecdsa", "sha2-384"),
    "ecdsa-with-SHA512": ("ecdsa", "sha2-512"),
    "ed25519": ("ed25519", ""),
    "ed448": ("ed448", ""),
}

# digests that make a certificate signature forgeable / deprecated
WEAK_SIG_HASHES = {"md5", "sha1"}


def _load(path: str) -> list[x509.Certificate]:
    data = open(path, "rb").read()
    certs: list[x509.Certificate] = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            certs = x509.load_pem_x509_certificates(data)
        except Exception:
            pass
    else:
        try:
            certs = [x509.load_der_x509_certificate(data)]
        except Exception:
            pass
    return certs


@register("certs")
def run(inv: Inventory, cert_dir: str, owner_map: dict | None = None, **_) -> dict:
    n_files = n_certs = n_weak = 0
    owner_map = owner_map or {}
    for root, _dirs, files in os.walk(cert_dir):
        for fn in files:
            if os.path.splitext(fn)[1].lower() not in EXTS:
                continue
            path = os.path.join(root, fn)
            certs = _load(path)
            if not certs:
                continue
            n_files += 1
            for cert in certs:
                n_certs += 1
                n_weak += _observe_cert(inv, cert, path, owner_map.get(fn))
    links = inv.link_chain()
    stats = {"files": n_files, "certificates": n_certs, "weak_findings": n_weak,
             "chain_links": links}
    inv.record_collector("certs", stats)
    return stats


def _validity_tags(cert: x509.Certificate) -> list[str]:
    now = datetime.now(timezone.utc)
    days_left = (cert.not_valid_after_utc - now).days
    if days_left < 0:
        return ["expired"]
    if days_left < 90:
        return ["expiring-soon"]
    return []


def _observe_cert(inv: Inventory, cert: x509.Certificate, path: str,
                  owner: str | None) -> int:
    subj = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    tags = _validity_tags(cert)
    base = dict(collector="certs", owner=owner)
    weak = 0
    cert_weak_tags = set(tags)         # accumulate for the certificate node

    def occ(evidence, confidence=1.0, extra_tags=None):
        return Occurrence(locator=path, evidence=evidence, confidence=confidence,
                          tags=tags + (extra_tags or []), **base)

    key_ref = None
    sig_ref = None

    # --- subject public key ---
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        bits = pub.key_size
        wk = ["weak-key"] if bits < RSA_MIN_BITS else []
        weak += 1 if wk else 0
        cert_weak_tags |= set(wk)
        note = f", below {RSA_MIN_BITS}-bit minimum" if wk else ""
        a = inv.observe("pk-encryption", "rsa",
                        occ(f"RSA-{bits} public key in cert for {subj}{note}", extra_tags=wk),
                        key_length=bits)
        key_ref = a.key
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        curve = pub.curve.name
        wk = ["weak-curve"] if curve in WEAK_CURVES else []
        weak += 1 if wk else 0
        cert_weak_tags |= set(wk)
        note = " (weak curve)" if wk else ""
        a = inv.observe("signature", "ecdsa",
                        occ(f"EC public key ({curve}){note} for {subj}", extra_tags=wk),
                        params=curve, key_length=pub.curve.key_size)
        key_ref = a.key
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        a = inv.observe("signature", "ed25519",
                        occ(f"Ed25519 key for {subj}"), key_length=256)
        key_ref = a.key
    elif isinstance(pub, ed448.Ed448PublicKey):
        a = inv.observe("signature", "ed448",
                        occ(f"Ed448 key for {subj}"), key_length=448)
        key_ref = a.key
    elif isinstance(pub, dsa.DSAPublicKey):
        bits = pub.key_size
        wk = ["weak-key"] if bits < RSA_MIN_BITS else []
        weak += 1 if wk else 0
        cert_weak_tags |= set(wk)
        a = inv.observe("signature", "dsa",
                        occ(f"DSA-{bits} key for {subj}", extra_tags=wk), key_length=bits)
        key_ref = a.key

    # --- certificate's own signature algorithm (composite) ---
    sig_name = cert.signature_algorithm_oid._name
    mapped = SIG_ALG.get(sig_name)
    if mapped:
        sig_alg, sig_hash = mapped
        weak_hash = sig_hash in WEAK_SIG_HASHES
        wk = ["weak-signature"] if weak_hash else []
        weak += 1 if weak_hash else 0
        cert_weak_tags |= set(wk)
        label = f"{sig_hash}-{sig_alg}" if sig_hash else sig_alg
        note = " (forgeable digest)" if weak_hash else ""
        # the signing operation itself, keyed with the digest as params so
        # SHA1-RSA is a distinct asset from SHA256-RSA
        a = inv.observe("signature", sig_alg,
                        occ(f"certificate signed with {label}{note} by issuer "
                            f"{issuer}", extra_tags=wk),
                        params=f"cert-sig:{sig_hash}" if sig_hash else "cert-sig")
        sig_ref = a.key
        # also surface the weak digest itself for chain-wide hash inventory
        if weak_hash:
            inv.observe("hash", sig_hash,
                        occ(f"weak digest {sig_hash} in certificate signature",
                            extra_tags=["weak-signature"]))

    # --- register the certificate as a chain node ---
    is_ca = _is_ca(cert)
    self_signed = subj == issuer
    inv.add_certificate(Certificate(
        subject=subj, issuer=issuer, locator=path,
        serial=format(cert.serial_number, "x"),
        not_after=cert.not_valid_after_utc.isoformat(),
        is_ca=is_ca, self_signed=self_signed,
        key_ref=key_ref, sig_ref=sig_ref, weak_tags=cert_weak_tags,
    ))
    return weak


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bool(bc.ca)
    except x509.ExtensionNotFound:
        return False
