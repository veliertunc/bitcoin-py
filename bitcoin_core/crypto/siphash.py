"""SipHash-2-4, used by compact block filters and protocol hash tables."""

from __future__ import annotations


_MASK64 = (1 << 64) - 1


def siphash24(key: bytes, message: bytes) -> int:
    """Return the 64-bit SipHash-2-4 digest as an unsigned little-endian integer."""
    if len(key) != 16:
        raise ValueError("SipHash key must contain exactly 16 bytes")
    k0 = int.from_bytes(key[:8], "little")
    k1 = int.from_bytes(key[8:], "little")
    v0 = 0x736F6D6570736575 ^ k0
    v1 = 0x646F72616E646F6D ^ k1
    v2 = 0x6C7967656E657261 ^ k0
    v3 = 0x7465646279746573 ^ k1

    def rotate(value: int, bits: int) -> int:
        return ((value << bits) | (value >> (64 - bits))) & _MASK64

    def round_once() -> tuple[int, int, int, int]:
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & _MASK64
        v1 = rotate(v1, 13) ^ v0
        v0 = rotate(v0, 32)
        v2 = (v2 + v3) & _MASK64
        v3 = rotate(v3, 16) ^ v2
        v0 = (v0 + v3) & _MASK64
        v3 = rotate(v3, 21) ^ v0
        v2 = (v2 + v1) & _MASK64
        v1 = rotate(v1, 17) ^ v2
        v2 = rotate(v2, 32)
        return v0, v1, v2, v3

    offset = 0
    while offset + 8 <= len(message):
        word = int.from_bytes(message[offset : offset + 8], "little")
        v3 ^= word
        round_once()
        round_once()
        v0 ^= word
        offset += 8

    final = (len(message) & 0xFF) << 56
    for index, byte in enumerate(message[offset:]):
        final |= byte << (8 * index)
    v3 ^= final
    round_once()
    round_once()
    v0 ^= final
    v2 ^= 0xFF
    round_once()
    round_once()
    round_once()
    round_once()
    return (v0 ^ v1 ^ v2 ^ v3) & _MASK64
