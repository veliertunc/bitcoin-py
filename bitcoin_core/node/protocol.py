"""Dispatch established peer messages to header and block synchronization."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.network.messages import decode_inventory, encode_inventory
from bitcoin_core.network.protocol import Message
from bitcoin_core.node.block_sync import BlockSynchronizer
from bitcoin_core.node.relay import MempoolRelay
from bitcoin_core.node.sync import HeaderSynchronizer


@dataclass(slots=True)
class NodeProtocol:
    """Compose peer handshake, header sync, and block sync message handling."""

    headers: HeaderSynchronizer
    blocks: BlockSynchronizer
    peers: Callable[[], list[PeerConnection]]
    relay: MempoolRelay | None = None

    async def __call__(self, peer: PeerConnection, message: Message) -> None:
        if message.command == "verack":
            if peer.established:
                await self.headers.begin(peer)
                await self.blocks.request_more(self.peers())
        elif message.command == "getheaders":
            await peer.send("headers", self.headers.serve_getheaders(message.payload))
        elif message.command == "headers":
            await self.headers.handle(peer, message)
            await self.blocks.request_more(self.peers())
        elif message.command == "block":
            await self.blocks.handle(peer, message, self.peers())
        elif message.command == "getdata":
            try:
                inventory = decode_inventory(message.payload)
            except ValueError:
                await peer.close()
                raise
            missing = inventory
            if self.relay is not None:
                missing = await self.relay.serve_inventory(peer, missing)
            missing = await self.blocks.serve_inventory(peer, missing)
            if missing:
                await peer.send("notfound", encode_inventory(missing))
        elif message.command in ("inv", "tx") and self.relay is not None:
            await self.relay.handle(peer, message, self.peers())
        elif message.command == "notfound":
            self.blocks.handle_notfound(peer, message.payload)
