"""Bitcoin Core compatible Base58 and Base58Check encoding."""

from __future__ import annotations

from bitcoin_core.crypto.hashes import hash256

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {char: index for index, char in enumerate(ALPHABET)}


class Base58Error(ValueError):
    """Raised when a Base58 string is malformed or has an invalid checksum."""


def encode_base58(data: bytes) -> str:
    """Encode bytes using the Bitcoin Base58 alphabet."""
    zeroes = len(data) - len(data.lstrip(b"\0"))
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def decode_base58(text: str, *, max_length: int = 10_000) -> bytes:
    """Decode Base58, allowing surrounding ASCII whitespace as Core does."""
    if "\0" in text:
        raise Base58Error("NUL byte in Base58 string")
    text = text.strip(" \t\n\r\v\f")
    zeroes = len(text) - len(text.lstrip("1"))
    value = 0
    for char in text:
        digit = _INDEX.get(char)
        if digit is None:
            raise Base58Error(f"invalid Base58 character: {char!r}")
        value = value * 58 + digit
        if (value.bit_length() + 7) // 8 + zeroes > max_length:
            raise Base58Error("decoded Base58 value exceeds maximum length")
    payload = value.to_bytes((value.bit_length() + 7) // 8, "big")
    result = b"\0" * zeroes + payload
    if len(result) > max_length:
        raise Base58Error("decoded Base58 value exceeds maximum length")
    return result


def encode_base58_check(payload: bytes) -> str:
    """Encode a payload with its four-byte double-SHA-256 checksum."""
    return encode_base58(payload + hash256(payload)[:4])


def decode_base58_check(text: str, *, max_length: int = 10_000) -> bytes:
    """Decode Base58Check and return the payload after checksum validation."""
    decoded = decode_base58(text, max_length=max_length + 4)
    if len(decoded) < 4:
        raise Base58Error("Base58Check value is shorter than its checksum")
    payload, checksum = decoded[:-4], decoded[-4:]
    if hash256(payload)[:4] != checksum:
        raise Base58Error("invalid Base58Check checksum")
    if len(payload) > max_length:
        raise Base58Error("decoded Base58Check payload exceeds maximum length")
    return payload
