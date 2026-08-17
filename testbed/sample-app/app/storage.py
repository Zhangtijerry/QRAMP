"""Testbed sample app — storage module (mixed good/indeterminate crypto)."""
import hashlib

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import rsa


def content_digest(blob: bytes) -> str:
    # OK: SHA-256 (quantum_weakened but acceptable near-term)
    return hashlib.sha256(blob).hexdigest()


def strong_digest(blob: bytes) -> str:
    # OK: SHA-512
    return hashlib.sha512(blob).hexdigest()


def encrypt_blob(blob: bytes, key: bytes) -> bytes:
    # AES-256-GCM (good)
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(blob)
    return cipher.nonce + tag + ct


def make_backup_key(size_from_config: int):
    # Indeterminate: key_size computed at run time -> low confidence occurrence
    return rsa.generate_private_key(public_exponent=65537, key_size=size_from_config)


def weak_aes_key(key: bytes):
    # BAD: AES-128 explicitly (quantum_weakened -> increase-parameters to 256)
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC)  # 128-bit key material by convention
    return cipher

