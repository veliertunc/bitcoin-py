"""Codecs for common Bitcoin P2P inventory and header messages."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import BinaryIO

from bitcoin_core.primitives.block import BlockHeader
from bitcoin_core.serialization.compact_size import read_compact_size, write_compact_size

MAX_INV_ENTRIES = 50_000
MAX_HEADERS = 2_000
MAX_BLOCK_LOCATORS = 101


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("truncated P2P message payload")
    return data


def _ensure_consumed(stream: BytesIO) -> None:
    if stream.read(1):
        raise ValueError("trailing bytes in P2P message payload")


@dataclass(frozen=True, slots=True)
class InventoryVector:
    """Inventory type and 256-bit object hash in wire byte order."""

    type: int
    hash: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.type <= 0xFFFFFFFF:
            raise ValueError("inventory type must fit in uint32")
        if len(self.hash) != 32:
            raise ValueError("inventory hash must contain 32 bytes")

    def serialize(self) -> bytes:
        return self.type.to_bytes(4, "little") + self.hash


def encode_inventory(entries: tuple[InventoryVector, ...] | list[InventoryVector]) -> bytes:
    """Serialize an inv/getdata/notfound inventory vector."""
    if len(entries) > MAX_INV_ENTRIES:
        raise ValueError("inventory vector exceeds 50,000 entries")
    return write_compact_size(len(entries)) + b"".join(entry.serialize() for entry in entries)


def decode_inventory(payload: bytes) -> tuple[InventoryVector, ...]:
    """Parse an inv/getdata/notfound inventory payload."""
    stream = BytesIO(payload)
    count = read_compact_size(stream)
    if count > MAX_INV_ENTRIES:
        raise ValueError("inventory vector exceeds 50,000 entries")
    entries = tuple(
        InventoryVector(int.from_bytes(_read_exact(stream, 4), "little"), _read_exact(stream, 32))
        for _ in range(count)
    )
    _ensure_consumed(stream)
    return entries


@dataclass(frozen=True, slots=True)
class GetHeaders:
    """getheaders request with locator hashes and a stop hash."""

    protocol_version: int
    locators: tuple[bytes, ...]
    stop_hash: bytes = bytes(32)

    def serialize(self) -> bytes:
        if not -(1 << 31) <= self.protocol_version < (1 << 31):
            raise ValueError("protocol version must fit in int32")
        if len(self.locators) > MAX_BLOCK_LOCATORS or any(len(item) != 32 for item in self.locators):
            raise ValueError("invalid block locator list")
        if len(self.stop_hash) != 32:
            raise ValueError("stop hash must contain 32 bytes")
        return (
            self.protocol_version.to_bytes(4, "little", signed=True)
            + write_compact_size(len(self.locators))
            + b"".join(self.locators)
            + self.stop_hash
        )

    @classmethod
    def deserialize(cls, payload: bytes) -> GetHeaders:
        stream = BytesIO(payload)
        version = int.from_bytes(_read_exact(stream, 4), "little", signed=True)
        count = read_compact_size(stream)
        if count > MAX_BLOCK_LOCATORS:
            raise ValueError("block locator list exceeds limit")
        locators = tuple(_read_exact(stream, 32) for _ in range(count))
        stop_hash = _read_exact(stream, 32)
        _ensure_consumed(stream)
        return cls(version, locators, stop_hash)


def encode_headers(headers: tuple[BlockHeader, ...] | list[BlockHeader]) -> bytes:
    """Serialize a headers message, including the required zero tx-count per header."""
    if len(headers) > MAX_HEADERS:
        raise ValueError("headers message exceeds 2,000 entries")
    return write_compact_size(len(headers)) + b"".join(header.serialize() + b"\0" for header in headers)


def decode_headers(payload: bytes) -> tuple[BlockHeader, ...]:
    """Parse a headers message and enforce each zero transaction-count marker."""
    stream = BytesIO(payload)
    count = read_compact_size(stream)
    if count > MAX_HEADERS:
        raise ValueError("headers message exceeds 2,000 entries")
    headers = []
    for _ in range(count):
        headers.append(BlockHeader.deserialize(_read_exact(stream, 80)))
        if read_compact_size(stream) != 0:
            raise ValueError("headers message transaction count must be zero")
    _ensure_consumed(stream)
    return tuple(headers)
