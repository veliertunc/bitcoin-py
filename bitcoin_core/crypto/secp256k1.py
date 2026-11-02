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


def is_strict_der_signature(encoded_with_hash_type: bytes) -> bool:
    """Check the BIP66 encoding rules without requiring valid ECDSA scalars."""
    size = len(encoded_with_hash_type)
    if not 9 <= size <= 73 or encoded_with_hash_type[0] != 0x30:
        return False
    if encoded_with_hash_type[1] != size - 3 or encoded_with_hash_type[2] != 0x02:
        return False
    r_size = encoded_with_hash_type[3]
    if r_size == 0 or 5 + r_size >= size:
        return False
    r_first = encoded_with_hash_type[4]
    if r_first & 0x80:
        return False
    if r_size > 1 and r_first == 0 and not encoded_with_hash_type[5] & 0x80:
        return False
    s_tag = 4 + r_size
    if encoded_with_hash_type[s_tag] != 0x02:
        return False
    s_size = encoded_with_hash_type[s_tag + 1]
    if s_size == 0 or r_size + s_size + 7 != size:
        return False
    s_first = encoded_with_hash_type[s_tag + 2]
    if s_first & 0x80:
        return False
    if s_size > 1 and s_first == 0 and not encoded_with_hash_type[s_tag + 3] & 0x80:
        return False
    return True


def parse_der_signature_lax(encoded: bytes) -> tuple[int, int]:
    """Parse the historical libsecp256k1 lax-DER signature format."""
    position = 0
    if not encoded or encoded[position] != 0x30:
        raise ValueError("invalid ECDSA sequence tag")
    position += 1

    def read_length(*, allow_long: bool) -> int:
        nonlocal position
        if position >= len(encoded):
            raise ValueError("truncated ECDSA length")
        length = encoded[position]
        position += 1
        if not length & 0x80:
            return length
        if not allow_long:
            raise ValueError("long ECDSA length is not allowed")
        byte_count = length & 0x7F
        if byte_count > len(encoded) - position:
            raise ValueError("truncated long ECDSA length")
        while byte_count and encoded[position] == 0:
            position += 1
            byte_count -= 1
        if byte_count >= 8:
            raise ValueError("ECDSA length overflows size_t")
        result = 0
        while byte_count:
            result = (result << 8) | encoded[position]
            position += 1
            byte_count -= 1
        return result

    # The historical parser intentionally skips, but does not decode, this length.
    if position >= len(encoded):
        raise ValueError("truncated ECDSA sequence length")
    sequence_length = encoded[position]
    position += 1
    if sequence_length & 0x80:
        sequence_length &= 0x7F
        if sequence_length > len(encoded) - position:
            raise ValueError("truncated long ECDSA sequence length")
        position += sequence_length
    if position >= len(encoded) or encoded[position] != 0x02:
        raise ValueError("invalid ECDSA r tag")
    position += 1
    r_length = read_length(allow_long=True)
    if r_length > len(encoded) - position:
        raise ValueError("truncated ECDSA r integer")
    r_data = encoded[position : position + r_length]
    position += r_length

    if position >= len(encoded) or encoded[position] != 0x02:
        raise ValueError("invalid ECDSA s tag")
    position += 1
    s_length = read_length(allow_long=True)
    if s_length > len(encoded) - position:
        raise ValueError("truncated ECDSA s integer")
    s_data = encoded[position : position + s_length]

    r_data = r_data.lstrip(b"\x00")
    s_data = s_data.lstrip(b"\x00")
    if len(r_data) > 32 or len(s_data) > 32:
        return 0, 0
    r = int.from_bytes(r_data, "big")
    s = int.from_bytes(s_data, "big")
    if not 1 <= r < ORDER or not 1 <= s < ORDER:
        return 0, 0
    return r, s


def verify_ecdsa(
    message_hash: bytes,
    der_signature: bytes,
    public_key: bytes,
    *,
    low_s: bool = False,
    strict_der: bool = True,
) -> bool:
    """Verify strict-DER or historical lax-DER ECDSA over a 32-byte digest."""
    if len(message_hash) != 32:
        return False
    try:
        parser = parse_der_signature if strict_der else parse_der_signature_lax
        r, s = parser(der_signature)
        point = parse_public_key(public_key)
    except ValueError:
        return False
    if not 1 <= r < ORDER or not 1 <= s < ORDER:
        return False
    if low_s and s > ORDER // 2:
        return False
    z = int.from_bytes(message_hash, "big")
    inverse = pow(s, -1, ORDER)
    candidate = _point_add(_point_mul(z * inverse % ORDER, GENERATOR), _point_mul(r * inverse % ORDER, point))
    return candidate is not None and candidate[0] % ORDER == r
