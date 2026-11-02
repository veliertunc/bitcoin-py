"""Header synchronization over established P2P connections."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.network.messages import MAX_HEADERS, GetHeaders, decode_headers, encode_headers
from bitcoin_core.network.protocol import MAINNET_MAGIC, Message, encode_message
from bitcoin_core.node.chain import BlockIndex, HeaderChain, HeaderValidationError


def block_locator(chain: HeaderChain) -> tuple[bytes, ...]:
    """Build a locator that walks recent headers densely and older headers sparsely."""
    if chain.tip is None:
        return ()
    locator: list[bytes] = []
    current: int | None = chain.tip.height
    step = 1
    while current is not None:
        index = chain.tip.ancestor(current)
        if index is None:
            break
        locator.append(index.block_hash)
        if current == 0:
            break
        current = max(0, current - step)
        if len(locator) >= 10:
            step *= 2
    return tuple(locator)


@dataclass(slots=True)
class HeaderSynchronizer:
    """Request and validate headers received from a peer."""

    chain: HeaderChain
    protocol_version: int = 70_016
    magic: bytes = MAINNET_MAGIC
    persist_header: Callable[[BlockIndex], object] | None = None

    def request(self) -> bytes:
        """Return an encoded getheaders request from the current active tip."""
        request = GetHeaders(self.protocol_version, block_locator(self.chain))
        return encode_message("getheaders", request.serialize(), self.magic)

    async def begin(self, peer: PeerConnection) -> None:
        """Request headers from one established peer."""
        await peer.send("getheaders", GetHeaders(self.protocol_version, block_locator(self.chain)).serialize())

    def serve_getheaders(self, payload: bytes) -> bytes:
        """Build an encoded headers response for a peer's locator request."""
        request = GetHeaders.deserialize(payload)
        tip = self.chain.tip
        if tip is None:
            headers = ()
        else:
            start_height = -1
            for block_hash in request.locators:
                candidate = self.chain.indexes.get(block_hash)
                if candidate is not None:
                    active_candidate = tip.ancestor(candidate.height)
                    if active_candidate is candidate:
                        start_height = candidate.height
                        break
            result = []
            for height in range(start_height + 1, tip.height + 1):
                index = tip.ancestor(height)
                if index is None:
                    break
                result.append(index.header)
                if index.block_hash == request.stop_hash or len(result) >= MAX_HEADERS:
                    break
            headers = tuple(result)
        return encode_headers(headers)

    async def handle(self, peer: PeerConnection, message: Message) -> int:
        """Validate a headers response and continue if it filled a full batch."""
        if message.command != "headers":
            return 0
        try:
            headers = decode_headers(message.payload)
            for header in headers:
                index = self.chain.add_header(header)
                if self.persist_header is not None:
                    self.persist_header(index)
        except (ValueError, HeaderValidationError):
            await peer.close()
            raise
        if len(headers) == MAX_HEADERS:
            await self.begin(peer)
        return len(headers)
