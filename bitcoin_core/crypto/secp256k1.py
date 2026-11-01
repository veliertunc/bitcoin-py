"""Minimal secp256k1 public-key parsing and ECDSA verification."""

from __future__ import annotations

FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = tuple[int, int] | None


def _point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % FIELD == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, FIELD) % FIELD
    else:
        slope = (y2 - y1) * pow((x2 - x1) % FIELD, -1, FIELD) % FIELD
    x3 = (slope * slope - x1 - x2) % FIELD
    return x3, (slope * (x1 - x3) - y1) % FIELD


def _point_mul(scalar: int, point: Point) -> Point:
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def parse_public_key(encoded: bytes) -> Point:
    """Parse a standard compressed or uncompressed secp256k1 public key."""
    if len(encoded) == 33 and encoded[0] in (2, 3):
        x = int.from_bytes(encoded[1:], "big")
        if x >= FIELD:
            raise ValueError("public key x-coordinate out of range")
        y_squared = (pow(x, 3, FIELD) + 7) % FIELD
        y = pow(y_squared, (FIELD + 1) // 4, FIELD)
        if y * y % FIELD != y_squared:
            raise ValueError("public key is not on secp256k1")
        if y & 1 != encoded[0] & 1:
            y = FIELD - y
        return x, y
    if len(encoded) == 65 and encoded[0] == 4:
        x = int.from_bytes(encoded[1:33], "big")
        y = int.from_bytes(encoded[33:], "big")
        if x >= FIELD or y >= FIELD or (y * y - x * x * x - 7) % FIELD:
            raise ValueError("public key is not on secp256k1")
        return x, y
    raise ValueError("invalid secp256k1 public-key encoding")


def parse_der_signature(encoded: bytes) -> tuple[int, int]:
    """Parse a strict DER-encoded ECDSA signature (without sighash byte)."""
    if not 8 <= len(encoded) <= 72 or encoded[0] != 0x30 or encoded[1] != len(encoded) - 2:
        raise ValueError("invalid DER signature sequence")
    if encoded[2] != 0x02:
        raise ValueError("invalid DER r integer")
    r_size = encoded[3]
    r_start = 4
    r_end = r_start + r_size
    if r_size == 0 or r_end + 2 > len(encoded) or encoded[r_end] != 0x02:
        raise ValueError("invalid DER r length")
    if encoded[r_start] & 0x80 or (r_size > 1 and encoded[r_start] == 0 and not (encoded[r_start + 1] & 0x80)):
        raise ValueError("non-canonical DER r integer")
    s_size = encoded[r_end + 1]
    s_start = r_end + 2
    s_end = s_start + s_size
    if s_size == 0 or s_end != len(encoded):
        raise ValueError("invalid DER s length")
    if encoded[s_start] & 0x80 or (s_size > 1 and encoded[s_start] == 0 and not (encoded[s_start + 1] & 0x80)):
        raise ValueError("non-canonical DER s integer")
    r = int.from_bytes(encoded[r_start:r_end], "big")
    s = int.from_bytes(encoded[s_start:s_end], "big")
    if not 1 <= r < ORDER or not 1 <= s < ORDER:
        raise ValueError("ECDSA scalar out of range")
    return r, s


def verify_ecdsa(message_hash: bytes, der_signature: bytes, public_key: bytes, *, low_s: bool = False) -> bool:
    """Verify strict DER ECDSA over a 32-byte message digest."""
    if len(message_hash) != 32:
        return False
    try:
        r, s = parse_der_signature(der_signature)
        point = parse_public_key(public_key)
    except ValueError:
        return False
    if low_s and s > ORDER // 2:
        return False
    z = int.from_bytes(message_hash, "big")
    inverse = pow(s, -1, ORDER)
    candidate = _point_add(_point_mul(z * inverse % ORDER, GENERATOR), _point_mul(r * inverse % ORDER, point))
    return candidate is not None and candidate[0] % ORDER == r
