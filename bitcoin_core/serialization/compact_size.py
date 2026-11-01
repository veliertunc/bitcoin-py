"""Canonical CompactSize integers from Bitcoin Core's serialization format."""

from __future__ import annotations

from typing import BinaryIO

MAX_COMPACT_SIZE = 0x02000000
MAX_UINT64 = 0xFFFFFFFFFFFFFFFF


def write_compact_size(value: int) -> bytes:
    """Serialize a non-negative integer using Bitcoin's CompactSize encoding."""
    if not 0 <= value <= MAX_UINT64:
        raise ValueError("CompactSize value must fit in uint64")
    if value < 253:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def read_compact_size(stream: BinaryIO, *, range_check: bool = True) -> int:
    """Read one canonical CompactSize value from a binary stream."""
    prefix = _read_exact(stream, 1)[0]
    if prefix < 253:
        value = prefix
    elif prefix == 253:
        value = int.from_bytes(_read_exact(stream, 2), "little")
        if value < 253:
            raise ValueError("non-canonical CompactSize")
    elif prefix == 254:
        value = int.from_bytes(_read_exact(stream, 4), "little")
        if value <= 0xFFFF:
            raise ValueError("non-canonical CompactSize")
    else:
        value = int.from_bytes(_read_exact(stream, 8), "little")
        if value <= 0xFFFFFFFF:
            raise ValueError("non-canonical CompactSize")
    if range_check and value > MAX_COMPACT_SIZE:
        raise ValueError("CompactSize value exceeds protocol limit")
    return value


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise EOFError("unexpected end of Bitcoin serialization")
    return data
