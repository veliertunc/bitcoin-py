"""BIP340 Schnorr signature verification for secp256k1."""

from __future__ import annotations

from bitcoin_core.crypto.secp256k1 import FIELD, GENERATOR, ORDER, Point, _point_add, _point_mul


def tagged_hash(tag: str, message: bytes) -> bytes:
    """Compute SHA256(SHA256(tag) || SHA256(tag) || message)."""
    import hashlib

    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def _lift_x(x: int) -> Point:
    if x >= FIELD:
        return None
    y_squared = (pow(x, 3, FIELD) + 7) % FIELD
    y = pow(y_squared, (FIELD + 1) // 4, FIELD)
    if y * y % FIELD != y_squared:
        return None
    if y & 1:
        y = FIELD - y
    return x, y


def verify_schnorr(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a 64-byte BIP340 signature against a 32-byte x-only public key."""
    if len(message) != 32 or len(signature) != 64 or len(public_key) != 32:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= FIELD or s >= ORDER:
        return False
    point = _lift_x(int.from_bytes(public_key, "big"))
    if point is None:
        return False
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", signature[:32] + public_key + message), "big"
    ) % ORDER
    candidate = _point_add(_point_mul(s, GENERATOR), _point_mul(-challenge % ORDER, point))
    return candidate is not None and candidate[1] % 2 == 0 and candidate[0] == r
