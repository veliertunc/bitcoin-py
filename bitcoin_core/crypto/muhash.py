"""Bitcoin Core's MuHash3072 accumulator for UTXO set commitments."""

from __future__ import annotations

from bitcoin_core.crypto.chacha20 import chacha20_block
from bitcoin_core.crypto.hashes import sha256

MUHASH_MODULUS = (1 << 3072) - 1_103_717
MUHASH_ELEMENT_SIZE = 384


def element_to_num(data: bytes) -> int:
    """Map a serialized UTXO element into the MuHash3072 field."""
    key = sha256(data)
    stream = b"".join(chacha20_block(key, counter=counter) for counter in range(MUHASH_ELEMENT_SIZE // 64))
    return int.from_bytes(stream, "little") % MUHASH_MODULUS


class MuHash3072:
    """Order-independent set accumulator represented as a numerator/denominator pair."""

    __slots__ = ("_numerator", "_denominator")

    def __init__(self) -> None:
        self._numerator = 1
        self._denominator = 1

    def insert(self, element: bytes) -> None:
        self._numerator = self._numerator * element_to_num(element) % MUHASH_MODULUS

    def remove(self, element: bytes) -> None:
        self._denominator = self._denominator * element_to_num(element) % MUHASH_MODULUS

    def combine(self, other: MuHash3072) -> None:
        self._numerator = self._numerator * other._numerator % MUHASH_MODULUS
        self._denominator = self._denominator * other._denominator % MUHASH_MODULUS

    def difference(self, other: MuHash3072) -> None:
        self._numerator = self._numerator * other._denominator % MUHASH_MODULUS
        self._denominator = self._denominator * other._numerator % MUHASH_MODULUS

    def finalize(self) -> bytes:
        """Return the single-SHA256 commitment in internal uint256 byte order."""
        quotient = self._numerator * pow(self._denominator, -1, MUHASH_MODULUS) % MUHASH_MODULUS
        return sha256(quotient.to_bytes(MUHASH_ELEMENT_SIZE, "little"))
