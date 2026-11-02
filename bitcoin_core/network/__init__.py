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
from .messages import GetBlocks, GetHeaders, InventoryVector, decode_headers, decode_inventory, encode_headers, encode_inventory
from .compact_filters import (
    decode_cfheaders,
    decode_filter_checkpoints,
    decode_filter_range,
    encode_cfcheckpt,
    encode_cfheaders,
    encode_cfilter,
)
from .version import NODE_COMPACT_FILTERS, NODE_NETWORK, NetworkAddress, VersionMessage
from .peer import PeerHandshake, PeerProtocolError, PeerState
from .connection import PeerConnection, PeerManager

__all__ = [
    "GetHeaders",
    "GetBlocks",
    "InventoryVector",
    "InvalidMessage",
    "MAINNET_MAGIC",
    "Message",
    "MessageParser",
    "NetworkAddress",
    "NODE_COMPACT_FILTERS",
    "NODE_NETWORK",
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
    "decode_cfheaders",
    "decode_filter_checkpoints",
    "decode_filter_range",
    "decode_inventory",
    "encode_headers",
    "encode_cfcheckpt",
    "encode_cfheaders",
    "encode_cfilter",
    "encode_inventory",
    "encode_message",
]
