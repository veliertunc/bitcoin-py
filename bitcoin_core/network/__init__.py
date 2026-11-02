"""Peer-to-peer protocol framing and message codecs."""

from .protocol import (
    MAINNET_MAGIC,
    REGTEST_MAGIC,
    SIGNET_MAGIC,
    TESTNET_MAGIC,
    TESTNET4_MAGIC,
    InvalidMessage,
    Message,
    MessageParser,
    encode_message,
)
from .messages import GetHeaders, InventoryVector, decode_headers, decode_inventory, encode_headers, encode_inventory
from .version import NetworkAddress, VersionMessage
from .peer import PeerHandshake, PeerProtocolError, PeerState
from .connection import PeerConnection, PeerManager

__all__ = [
    "GetHeaders",
    "InventoryVector",
    "InvalidMessage",
    "MAINNET_MAGIC",
    "Message",
    "MessageParser",
    "NetworkAddress",
    "PeerHandshake",
    "PeerConnection",
    "PeerManager",
    "PeerProtocolError",
    "PeerState",
    "REGTEST_MAGIC",
    "SIGNET_MAGIC",
    "TESTNET_MAGIC",
    "TESTNET4_MAGIC",
    "VersionMessage",
    "decode_headers",
    "decode_inventory",
    "encode_headers",
    "encode_inventory",
    "encode_message",
]
