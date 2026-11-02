"""Network-address and version-handshake message codecs."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from io import BytesIO

from bitcoin_core.serialization.compact_size import read_compact_size, write_compact_size

MIN_VERSION_WITH_ADDR = 106
MIN_VERSION_WITH_RELAY = 70_001
MAX_USER_AGENT_LENGTH = 256
NODE_NETWORK = 1
NODE_COMPACT_FILTERS = 1 << 6


def _read_exact(stream: BytesIO, length: int) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("truncated version message")
    return data


@dataclass(frozen=True, slots=True)
class NetworkAddress:
    """P2P address without a timestamp, as embedded in version messages."""

    services: int
    ip: ipaddress.IPv6Address | ipaddress.IPv4Address
    port: int

    def __post_init__(self) -> None:
        if not 0 <= self.services <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("services must fit in uint64")
        if not 0 <= self.port <= 0xFFFF:
            raise ValueError("port must fit in uint16")

    def serialize(self) -> bytes:
        address = self.ip.ipv4_mapped if isinstance(self.ip, ipaddress.IPv6Address) else None
        if address is not None:
            address_bytes = self.ip.packed
        elif isinstance(self.ip, ipaddress.IPv4Address):
            address_bytes = ipaddress.IPv6Address(f"::ffff:{self.ip}").packed
        else:
            address_bytes = self.ip.packed
        return self.services.to_bytes(8, "little") + address_bytes + self.port.to_bytes(2, "big")

    @classmethod
    def deserialize(cls, stream: BytesIO) -> NetworkAddress:
        services = int.from_bytes(_read_exact(stream, 8), "little")
        raw_ip = _read_exact(stream, 16)
        address = ipaddress.IPv6Address(raw_ip)
        ip: ipaddress.IPv6Address | ipaddress.IPv4Address = address.ipv4_mapped or address
        port = int.from_bytes(_read_exact(stream, 2), "big")
        return cls(services, ip, port)


@dataclass(frozen=True, slots=True)
class VersionMessage:
    """The version handshake fields used to establish a P2P connection."""

    protocol_version: int
    services: int
    timestamp: int
    receiver: NetworkAddress
    sender: NetworkAddress | None = None
    nonce: int = 0
    user_agent: str = ""
    start_height: int = 0
    relay: bool | None = None

    def serialize(self) -> bytes:
        if not -(1 << 31) <= self.protocol_version < (1 << 31):
            raise ValueError("protocol version must fit in int32")
        if not 0 <= self.services <= 0xFFFFFFFFFFFFFFFF or not 0 <= self.nonce <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("services and nonce must fit in uint64")
        if not -(1 << 63) <= self.timestamp < (1 << 63):
            raise ValueError("timestamp must fit in int64")
        if not -(1 << 31) <= self.start_height < (1 << 31):
            raise ValueError("start height must fit in int32")
        user_agent = self.user_agent.encode("utf-8")
        if len(user_agent) > MAX_USER_AGENT_LENGTH:
            raise ValueError("user agent exceeds 256 bytes")
        payload = bytearray(self.protocol_version.to_bytes(4, "little", signed=True))
        payload.extend(self.services.to_bytes(8, "little"))
        payload.extend(self.timestamp.to_bytes(8, "little", signed=True))
        if self.protocol_version >= MIN_VERSION_WITH_ADDR:
            payload.extend(self.receiver.serialize())
            payload.extend((self.sender or NetworkAddress(0, ipaddress.IPv6Address("::"), 0)).serialize())
            payload.extend(self.nonce.to_bytes(8, "little"))
            payload.extend(write_compact_size(len(user_agent)))
            payload.extend(user_agent)
            payload.extend(self.start_height.to_bytes(4, "little", signed=True))
            if self.protocol_version >= MIN_VERSION_WITH_RELAY:
                payload.append(int(bool(self.relay)))
        return bytes(payload)

    @classmethod
    def deserialize(cls, payload: bytes) -> VersionMessage:
        stream = BytesIO(payload)
        version = int.from_bytes(_read_exact(stream, 4), "little", signed=True)
        services = int.from_bytes(_read_exact(stream, 8), "little")
        timestamp = int.from_bytes(_read_exact(stream, 8), "little", signed=True)
        if version < MIN_VERSION_WITH_ADDR:
            if stream.read(1):
                raise ValueError("trailing bytes in version message")
            return cls(version, services, timestamp, NetworkAddress(0, ipaddress.IPv6Address("::"), 0))
        receiver = NetworkAddress.deserialize(stream)
        sender = NetworkAddress.deserialize(stream)
        nonce = int.from_bytes(_read_exact(stream, 8), "little")
        user_agent_len = read_compact_size(stream)
        if user_agent_len > MAX_USER_AGENT_LENGTH:
            raise ValueError("user agent exceeds 256 bytes")
        try:
            user_agent = _read_exact(stream, user_agent_len).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("user agent is not valid UTF-8") from exc
        start_height = int.from_bytes(_read_exact(stream, 4), "little", signed=True)
        relay = None
        if version >= MIN_VERSION_WITH_RELAY and stream.tell() < len(payload):
            relay_byte = _read_exact(stream, 1)[0]
            if relay_byte not in (0, 1):
                raise ValueError("relay field must be a boolean")
            relay = bool(relay_byte)
        if stream.read(1):
            raise ValueError("trailing bytes in version message")
        return cls(version, services, timestamp, receiver, sender, nonce, user_agent, start_height, relay)
