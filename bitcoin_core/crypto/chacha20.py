"""ChaCha20 block function used by Bitcoin Core's MuHash element mapping."""

from __future__ import annotations

_MASK32 = 0xFFFFFFFF
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def chacha20_block(key: bytes, nonce: bytes = bytes(8), counter: int = 0) -> bytes:
    """Return one 64-byte Bitcoin Core ChaCha20Aligned keystream block."""
    if len(key) != 32 or len(nonce) != 8 or not 0 <= counter <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("ChaCha20Aligned requires a 32-byte key, 8-byte nonce, and uint64 counter")
    initial = [*_CONSTANTS]
    initial.extend(int.from_bytes(key[offset : offset + 4], "little") for offset in range(0, 32, 4))
    initial.extend((counter & _MASK32, counter >> 32))
    initial.extend(int.from_bytes(nonce[offset : offset + 4], "little") for offset in range(0, 8, 4))
    state = initial.copy()

    def rotate(value: int, bits: int) -> int:
        return ((value << bits) | (value >> (32 - bits))) & _MASK32

    def quarter(a: int, b: int, c: int, d: int) -> None:
        state[a] = (state[a] + state[b]) & _MASK32
        state[d] = rotate(state[d] ^ state[a], 16)
        state[c] = (state[c] + state[d]) & _MASK32
        state[b] = rotate(state[b] ^ state[c], 12)
        state[a] = (state[a] + state[b]) & _MASK32
        state[d] = rotate(state[d] ^ state[a], 8)
        state[c] = (state[c] + state[d]) & _MASK32
        state[b] = rotate(state[b] ^ state[c], 7)

    for _ in range(10):
        quarter(0, 4, 8, 12)
        quarter(1, 5, 9, 13)
        quarter(2, 6, 10, 14)
        quarter(3, 7, 11, 15)
        quarter(0, 5, 10, 15)
        quarter(1, 6, 11, 12)
        quarter(2, 7, 8, 13)
        quarter(3, 4, 9, 14)
    return b"".join(((state[i] + initial[i]) & _MASK32).to_bytes(4, "little") for i in range(16))
