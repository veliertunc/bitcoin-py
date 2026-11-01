"""Bech32, Bech32m, and SegWit address encoding (BIP 173/350)."""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_REVERSE = {char: index for index, char in enumerate(CHARSET)}
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_BECH32 = 1
_BECH32M = 0x2BC830A3


class Bech32Error(ValueError):
    """Raised for malformed Bech32 strings or SegWit addresses."""


def _polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(_GENERATOR):
            if (top >> bit) & 1:
                checksum ^= generator
    return checksum


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _checksum(hrp: str, data: list[int], constant: int) -> list[int]:
    polymod = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ constant
    return [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]


def _convert_bits(data: bytes | list[int], from_bits: int, to_bits: int, *, pad: bool) -> list[int]:
    accumulator = 0
    bit_count = 0
    result: list[int] = []
    max_value = (1 << to_bits) - 1
    max_accumulator = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise Bech32Error("input value exceeds bit-group width")
        accumulator = ((accumulator << from_bits) | value) & max_accumulator
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & max_value)
    if pad:
        if bit_count:
            result.append((accumulator << (to_bits - bit_count)) & max_value)
    elif bit_count >= from_bits or ((accumulator << (to_bits - bit_count)) & max_value):
        raise Bech32Error("invalid padding in bit conversion")
    return result


def encode(hrp: str, data: list[int], *, bech32m: bool = False) -> str:
    """Encode a human-readable part and 5-bit data using Bech32 or Bech32m."""
    if not hrp or any(ord(char) < 33 or ord(char) > 126 for char in hrp):
        raise Bech32Error("invalid human-readable part")
    if hrp.lower() != hrp and hrp.upper() != hrp:
        raise Bech32Error("mixed-case human-readable part")
    hrp = hrp.lower()
    if any(value < 0 or value > 31 for value in data):
        raise Bech32Error("data values must be 5-bit integers")
    constant = _BECH32M if bech32m else _BECH32
    result = hrp + "1" + "".join(CHARSET[value] for value in data + _checksum(hrp, data, constant))
    if len(result) > 90:
        raise Bech32Error("Bech32 string exceeds 90 characters")
    return result


def decode(text: str) -> tuple[str, list[int], bool]:
    """Decode Bech32/Bech32m; return (HRP, 5-bit data, is_bech32m)."""
    if not 8 <= len(text) <= 90:
        raise Bech32Error("Bech32 string length must be between 8 and 90")
    if any(ord(char) < 33 or ord(char) > 126 for char in text):
        raise Bech32Error("invalid character in Bech32 string")
    if text.lower() != text and text.upper() != text:
        raise Bech32Error("mixed-case Bech32 string")
    text = text.lower()
    separator = text.rfind("1")
    if separator < 1 or separator + 7 > len(text):
        raise Bech32Error("invalid Bech32 separator position")
    hrp = text[:separator]
    try:
        values = [_REVERSE[char] for char in text[separator + 1 :]]
    except KeyError as exc:
        raise Bech32Error(f"invalid Bech32 data character: {exc.args[0]!r}") from exc
    residue = _polymod(_hrp_expand(hrp) + values)
    if residue not in (_BECH32, _BECH32M):
        raise Bech32Error("invalid Bech32 checksum")
    return hrp, values[:-6], residue == _BECH32M


def encode_segwit_address(hrp: str, witness_version: int, program: bytes) -> str:
    """Encode a SegWit witness program as a Bech32 or Bech32m address."""
    if not 0 <= witness_version <= 16:
        raise Bech32Error("witness version must be between 0 and 16")
    if not 2 <= len(program) <= 40:
        raise Bech32Error("witness program must contain between 2 and 40 bytes")
    if witness_version == 0 and len(program) not in (20, 32):
        raise Bech32Error("version 0 witness program must contain 20 or 32 bytes")
    data = [witness_version] + _convert_bits(program, 8, 5, pad=True)
    return encode(hrp, data, bech32m=witness_version != 0)


def decode_segwit_address(text: str) -> tuple[str, int, bytes]:
    """Decode a SegWit address into (HRP, witness version, program)."""
    hrp, data, is_bech32m = decode(text)
    if not data:
        raise Bech32Error("missing witness version")
    version = data[0]
    if version > 16:
        raise Bech32Error("witness version must be between 0 and 16")
    if is_bech32m != (version != 0):
        raise Bech32Error("wrong checksum variant for witness version")
    program = bytes(_convert_bits(data[1:], 5, 8, pad=False))
    if not 2 <= len(program) <= 40:
        raise Bech32Error("witness program must contain between 2 and 40 bytes")
    if version == 0 and len(program) not in (20, 32):
        raise Bech32Error("version 0 witness program must contain 20 or 32 bytes")
    return hrp, version, program
