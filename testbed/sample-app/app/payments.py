"""Testbed sample app — payment module (deliberately uses legacy crypto)."""
import hashlib
import ssl
from Crypto.Cipher import DES, AES  # pycryptodome-style API (for AST detection)
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def legacy_token_hash(token: str) -> str:
    # BAD: MD5 for token integrity
    return hashlib.md5(token.encode()).hexdigest()


def fingerprint(data: bytes) -> str:
    # BAD: SHA-1
    return hashlib.sha1(data).hexdigest()


def encrypt_pan(pan: bytes, key: bytes) -> bytes:
    # BAD: single DES in ECB
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pan)


def make_signing_key():
    # BAD: RSA-2048 hard-coded (quantum-broken, and literal for externalise check)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_session_key():
    # ECDSA over P-256 (quantum-broken)
    return ec.generate_private_key(ec.SECP256R1())


def legacy_tls_context():
    # BAD: forcing TLS 1.0
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
