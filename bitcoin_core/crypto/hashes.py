"""Hash functions used in Bitcoin serialization and identifiers."""

from __future__ import annotations

import hashlib


def sha256(data: bytes) -> bytes:
    """Return SHA-256(data)."""
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """Return Bitcoin's double-SHA-256 digest."""
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    """Return RIPEMD-160(SHA-256(data)), used for legacy key hashes."""
    sha_digest = sha256(data)
    try:
        return hashlib.new("ripemd160", sha_digest).digest()
    except ValueError as exc:
        raise RuntimeError("this Python/OpenSSL build does not provide RIPEMD-160") from exc
