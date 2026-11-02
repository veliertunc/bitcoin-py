"""P2P version/verack handshake state machine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from bitcoin_core.network.protocol import MAINNET_MAGIC, Message, encode_message
from bitcoin_core.network.version import VersionMessage

MIN_PEER_PROTOCOL_VERSION = 70_001


class PeerState(Enum):
    NEW = auto()
    VERSION_SENT = auto()
    ESTABLISHED = auto()
    CLOSED = auto()


class PeerProtocolError(ValueError):
    """Raised when a peer violates the handshake protocol."""


@dataclass(slots=True)
class PeerHandshake:
    """Track version negotiation and return required handshake responses."""

    local_nonce: int
    magic: bytes = MAINNET_MAGIC
    minimum_version: int = MIN_PEER_PROTOCOL_VERSION
    state: PeerState = PeerState.NEW
    local_version: VersionMessage | None = None
    remote_version: VersionMessage | None = None
    sent_verack: bool = False
    received_verack: bool = False
    sent_wtxidrelay: bool = False
    received_wtxidrelay: bool = False

    def start(self, version: VersionMessage) -> bytes:
        """Construct the initial version message and transition to VERSION_SENT."""
        if self.state is not PeerState.NEW:
            raise PeerProtocolError("version handshake already started")
        if version.nonce != self.local_nonce:
            raise PeerProtocolError("local version nonce does not match peer session nonce")
        self.local_version = version
        self.state = PeerState.VERSION_SENT
        return encode_message("version", version.serialize(), self.magic)

    def receive(self, message: Message) -> tuple[bytes, ...]:
        """Process one received message and return encoded responses."""
        if self.state is PeerState.CLOSED:
            raise PeerProtocolError("peer connection is closed")
        responses: list[bytes] = []
        if message.command == "version":
            if self.state is PeerState.NEW or self.remote_version is not None:
                raise PeerProtocolError("unexpected or duplicate version message")
            remote = VersionMessage.deserialize(message.payload)
            if remote.protocol_version < self.minimum_version:
                self.close()
                raise PeerProtocolError("peer protocol version is too old")
            if remote.nonce == self.local_nonce:
                self.close()
                raise PeerProtocolError("self-connection detected")
            self.remote_version = remote
            responses.append(encode_message("verack", b"", self.magic))
            self.sent_verack = True
        elif message.command == "wtxidrelay":
            if (
                self.remote_version is None
                or self.received_verack
                or self.received_wtxidrelay
                or message.payload
                or self.remote_version.protocol_version < 70_016
            ):
                raise PeerProtocolError("unexpected or malformed wtxidrelay message")
            self.received_wtxidrelay = True
        elif message.command == "verack":
            if self.remote_version is None or self.received_verack or message.payload:
                raise PeerProtocolError("unexpected or malformed verack message")
            self.received_verack = True
        elif self.state is not PeerState.ESTABLISHED and message.command not in {
            "sendaddrv2", "wtxidrelay", "sendheaders", "sendcmpct"
        }:
            raise PeerProtocolError("received application message before handshake completion")
        if (
            self.local_version is not None
            and self.remote_version is not None
            and self.sent_verack
            and self.received_verack
        ):
            self.state = PeerState.ESTABLISHED
        return tuple(responses)

    def close(self) -> None:
        """Mark the peer connection closed."""
        self.state = PeerState.CLOSED
