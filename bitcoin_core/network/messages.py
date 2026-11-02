"""Codecs for common Bitcoin P2P inventory and header messages."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from io import BytesIO
from typing import BinaryIO

from bitcoin_core.network.version import NetworkAddress
from bitcoin_core.primitives.block import BlockHeader
from bitcoin_core.serialization.compact_size import read_compact_size, write_compact_size

MAX_INV_ENTRIES = 50_000
MAX_HEADERS = 2_000
MAX_BLOCK_LOCATORS = 101
MAX_ADDR_ENTRIES = 1_000
ADDRV2_IPV4 = 1
ADDRV2_IPV6 = 2
MAX_ADDRV2_ADDRESS_LENGTH = 512


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("truncated P2P message payload")
    return data


def _ensure_consumed(stream: BytesIO) -> None:
    if stream.read(1):
        raise ValueError("trailing bytes in P2P message payload")


@dataclass(frozen=True, slots=True)
class TimestampedAddress:
    """An address record as transmitted in an ``addr`` message."""

    timestamp: int
    address: NetworkAddress

    def __post_init__(self) -> None:
        if not 0 <= self.timestamp <= 0xFFFFFFFF:
            raise ValueError("address timestamp must fit in uint32")

    def serialize(self) -> bytes:
        return self.timestamp.to_bytes(4, "little") + self.address.serialize()


def encode_addr(entries: tuple[TimestampedAddress, ...] | list[TimestampedAddress]) -> bytes:
    """Serialize a legacy P2P ``addr`` message."""
    if len(entries) > MAX_ADDR_ENTRIES:
        raise ValueError("addr message exceeds 1,000 entries")
    return write_compact_size(len(entries)) + b"".join(item.serialize() for item in entries)


def decode_addr(payload: bytes) -> tuple[TimestampedAddress, ...]:
    """Parse a legacy P2P ``addr`` message and reject trailing data."""
    stream = BytesIO(payload)
    count = read_compact_size(stream)
    if count > MAX_ADDR_ENTRIES:
        raise ValueError("addr message exceeds 1,000 entries")
    entries = []
    for _ in range(count):
        timestamp = int.from_bytes(_read_exact(stream, 4), "little")
        entries.append(TimestampedAddress(timestamp, NetworkAddress.deserialize(stream)))
    _ensure_consumed(stream)
    return tuple(entries)


@dataclass(frozen=True, slots=True)
class AddressV2Entry:
    """BIP155 address record; unsupported network identifiers are preserved."""

    timestamp: int
    services: int
    network_id: int
    address: bytes
    port: int

    def __post_init__(self) -> None:
        if not 0 <= self.timestamp <= 0xFFFFFFFF:
            raise ValueError("address timestamp must fit in uint32")
        if not 0 <= self.services <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("address services must fit in uint64")
        if not 0 <= self.network_id <= 0xFF:
            raise ValueError("address network id must fit in uint8")
        if len(self.address) > MAX_ADDRV2_ADDRESS_LENGTH:
            raise ValueError("address-v2 address exceeds 512 bytes")
        if not 0 <= self.port <= 0xFFFF:
            raise ValueError("address port must fit in uint16")

    def to_network_address(self) -> TimestampedAddress | None:
        """Convert IPv4/IPv6 records to the address book's routable-IP form."""
        if self.network_id == ADDRV2_IPV4 and len(self.address) == 4:
            address = ipaddress.IPv4Address(self.address)
        elif self.network_id == ADDRV2_IPV6 and len(self.address) == 16:
            address = ipaddress.IPv6Address(self.address)
        else:
            return None
        return TimestampedAddress(
            self.timestamp,
            NetworkAddress(self.services, address, self.port),
        )


def _write_varint(value: int) -> bytes:
    """Encode Bitcoin Core's base-128 VARINT used for BIP155 services."""
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("VARINT must fit in uint64")
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            break
        value -= 1
    encoded.reverse()
    return bytes(encoded)


def _read_varint(stream: BytesIO) -> int:
    value = 0
    for _ in range(10):
        byte = _read_exact(stream, 1)[0]
        if value > (0xFFFFFFFFFFFFFFFF >> 7):
            raise ValueError("address services VARINT overflows uint64")
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80:
            if value == 0xFFFFFFFFFFFFFFFF:
                raise ValueError("address services VARINT overflows uint64")
            value += 1
            continue
        return value
    raise ValueError("address services VARINT is too long")


def encode_addrv2(entries: tuple[AddressV2Entry, ...] | list[AddressV2Entry]) -> bytes:
    """Serialize a BIP155 ``addrv2`` message."""
    if len(entries) > MAX_ADDR_ENTRIES:
        raise ValueError("addrv2 message exceeds 1,000 entries")
    result = bytearray(write_compact_size(len(entries)))
    for entry in entries:
        result.extend(entry.timestamp.to_bytes(4, "little"))
        result.extend(_write_varint(entry.services))
        result.append(entry.network_id)
        result.extend(write_compact_size(len(entry.address)))
        result.extend(entry.address)
        result.extend(entry.port.to_bytes(2, "big"))
    return bytes(result)


def decode_addrv2(payload: bytes) -> tuple[AddressV2Entry, ...]:
    """Parse BIP155 records, retaining unknown network IDs for safe forwarding."""
    stream = BytesIO(payload)
    count = read_compact_size(stream)
    if count > MAX_ADDR_ENTRIES:
        raise ValueError("addrv2 message exceeds 1,000 entries")
    entries = []
    for _ in range(count):
        timestamp = int.from_bytes(_read_exact(stream, 4), "little")
        services = _read_varint(stream)
        network_id = _read_exact(stream, 1)[0]
        address_length = read_compact_size(stream)
        if address_length > MAX_ADDRV2_ADDRESS_LENGTH:
            raise ValueError("addrv2 address exceeds 512 bytes")
        address = _read_exact(stream, address_length)
        port = int.from_bytes(_read_exact(stream, 2), "big")
        entries.append(AddressV2Entry(timestamp, services, network_id, address, port))
    _ensure_consumed(stream)
    return tuple(entries)


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


@dataclass(frozen=True, slots=True)
class GetBlocks:
    """Legacy block-inventory request using a locator and optional stop hash."""

    protocol_version: int
    locators: tuple[bytes, ...]
    stop_hash: bytes = bytes(32)

    def serialize(self) -> bytes:
        return GetHeaders(self.protocol_version, self.locators, self.stop_hash).serialize()

    @classmethod
    def deserialize(cls, payload: bytes) -> GetBlocks:
        request = GetHeaders.deserialize(payload)
        return cls(request.protocol_version, request.locators, request.stop_hash)


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
