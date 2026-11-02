"""Block download scheduling and active-chain connection."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from bitcoin_core.consensus.chainstate import BlockConnectionError, CoinsView, InputVerifier
from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.network.messages import InventoryVector, encode_inventory
from bitcoin_core.network.protocol import Message
from bitcoin_core.node.chain import HeaderChain
from bitcoin_core.node.storage import SQLiteNodeStore
from bitcoin_core.primitives.block import Block

MSG_WITNESS_BLOCK = 0x40000002
MAX_BLOCKS_IN_FLIGHT = 16
MAX_BLOCKS_PER_PEER = 4


@dataclass(slots=True)
class BlockSynchronizer:
    """Request missing blocks and connect them in active-chain order."""

    headers: HeaderChain
    store: SQLiteNodeStore
    coins: CoinsView
    params: ConsensusParams
    input_verifier: InputVerifier
    check_pow: bool = True
    in_flight: dict[bytes, PeerConnection] = field(default_factory=dict)
    pending: dict[bytes, tuple[Block, PeerConnection]] = field(default_factory=dict)

    async def request_more(self, peers: list[PeerConnection] | tuple[PeerConnection, ...]) -> int:
        """Fill the bounded block-download window using established peers."""
        peers = [peer for peer in peers if peer.established]
        if not peers or self.headers.tip is None:
            return 0
        tip_height = self.headers.tip.height
        next_height = self.store.best_height() + 1
        if next_height > tip_height:
            return 0
        per_peer: dict[PeerConnection, int] = defaultdict(int)
        for peer in self.in_flight.values():
            per_peer[peer] += 1
        for _block, peer in self.pending.values():
            per_peer[peer] += 1
        requested: dict[PeerConnection, list[InventoryVector]] = defaultdict(list)
        height = next_height
        while len(self.in_flight) + len(self.pending) < MAX_BLOCKS_IN_FLIGHT and height <= tip_height:
            index = self.headers.tip.ancestor(height)
            if index is None:
                break
            block_hash = index.block_hash
            if block_hash in self.in_flight or block_hash in self.pending:
                height += 1
                continue
            peer = min(peers, key=lambda candidate: per_peer[candidate])
            if per_peer[peer] >= MAX_BLOCKS_PER_PEER:
                break
            self.in_flight[block_hash] = peer
            per_peer[peer] += 1
            requested[peer].append(InventoryVector(MSG_WITNESS_BLOCK, block_hash))
            height += 1
        for peer, inventory in requested.items():
            await peer.send("getdata", encode_inventory(inventory))
        return sum(len(items) for items in requested.values())

    async def handle(self, peer: PeerConnection, message: Message, peers: list[PeerConnection]) -> bool:
        """Validate and connect a requested block, then refill the download window."""
        if message.command != "block":
            return False
        try:
            block = Block.deserialize(message.payload)
        except (EOFError, ValueError):
            await peer.close()
            raise
        block_hash = block.header.block_hash
        assigned_peer = self.in_flight.get(block_hash)
        if assigned_peer is None or assigned_peer is not peer:
            return False
        if block_hash not in self.headers.indexes:
            self.in_flight.pop(block_hash, None)
            await peer.close()
            raise BlockConnectionError("received block has no validated header")
        self.in_flight.pop(block_hash, None)
        self.pending[block_hash] = (block, peer)
        await self._connect_ready_blocks()
        await self.request_more(peers)
        return True

    async def _connect_ready_blocks(self) -> None:
        """Connect downloaded blocks in active-chain order."""
        if self.headers.tip is None:
            return
        height = self.store.best_height() + 1
        while height <= self.headers.tip.height:
            index = self.headers.tip.ancestor(height)
            if index is None:
                return
            pending = self.pending.get(index.block_hash)
            if pending is None:
                return
            block, source_peer = pending
            try:
                self.store.connect_block(
                    self.coins,
                    block,
                    index,
                    self.params,
                    input_verifier=self.input_verifier,
                    check_pow=self.check_pow,
                )
            except (ValueError, BlockConnectionError):
                self.pending.pop(index.block_hash, None)
                await source_peer.close()
                return
            self.pending.pop(index.block_hash, None)
            height += 1

    def peer_disconnected(self, peer: PeerConnection) -> tuple[bytes, ...]:
        """Release pending requests assigned to a disconnected peer."""
        abandoned = tuple(block_hash for block_hash, assigned in self.in_flight.items() if assigned is peer)
        for block_hash in abandoned:
            del self.in_flight[block_hash]
        return abandoned
