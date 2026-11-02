"""Parse Bitcoin P2P node endpoints shared by RPC and connection management."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NodeEndpoint:
    host: str
    port: int


def parse_node_endpoint(value: str, default_port: int) -> NodeEndpoint:
    """Parse ``host``, ``host:port``, or bracketed IPv6 endpoint notation."""
    if not value or value != value.strip() or any(character.isspace() for character in value):
        raise ValueError("node address cannot be empty or contain whitespace")
    host: str
    port = default_port
    if value.startswith("["):
        close = value.find("]")
        if close < 0:
            raise ValueError("bracketed IPv6 address is missing a closing bracket")
        host = value[1:close]
        try:
            host = str(ipaddress.IPv6Address(host))
        except ValueError as exc:
            raise ValueError("brackets are only valid around IPv6 addresses") from exc
        suffix = value[close + 1 :]
        if suffix:
            if not suffix.startswith(":"):
                raise ValueError("unexpected text after bracketed address")
            port = _parse_port(suffix[1:])
    else:
        try:
            host = str(ipaddress.ip_address(value))
        except ValueError:
            if value.count(":") == 1:
                candidate, _, port_text = value.rpartition(":")
                if not candidate:
                    raise ValueError("node hostname cannot be empty")
                host = candidate
                port = _parse_port(port_text)
            elif ":" in value:
                raise ValueError("IPv6 addresses with ports must use brackets")
            else:
                host = value
    if not host or len(host) > 253:
        raise ValueError("node hostname length is invalid")
    if not 1 <= port <= 65535:
        raise ValueError("node port must be between 1 and 65535")
    return NodeEndpoint(host, port)


def _parse_port(value: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError("node port must be a decimal integer")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("node port must be between 1 and 65535")
    return port
