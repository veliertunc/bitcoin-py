"""Block download scheduling and active-chain connection."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from bitcoin_core.consensus.chainstate import BlockConnectionError, CoinsView, InputVerifier
from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.network.messages import InventoryVector, decode_inventory, encode_inventory
from bitcoin_core.network.protocol import Message
from bitcoin_core.node.chain import BlockIndex, HeaderChain
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
        branch = self._branches()
        if branch is None:
            return 0
        _fork, _old_branch, new_branch = branch
        needed = {index.block_hash for index in new_branch}
        self.in_flight = {block_hash: peer for block_hash, peer in self.in_flight.items() if block_hash in needed}
        per_peer: dict[PeerConnection, int] = defaultdict(int)
        for peer in self.in_flight.values():
            per_peer[peer] += 1
        for block_hash, (_block, peer) in self.pending.items():
            if block_hash in needed:
                per_peer[peer] += 1
        requested: dict[PeerConnection, list[InventoryVector]] = defaultdict(list)
        outstanding = len(self.in_flight) + sum(1 for block_hash in self.pending if block_hash in needed)
        for index in new_branch:
            if outstanding >= MAX_BLOCKS_IN_FLIGHT:
                break
            block_hash = index.block_hash
            if block_hash in self.in_flight or block_hash in self.pending or self.store.has_block(block_hash):
                continue
            peer = min(peers, key=lambda candidate: per_peer[candidate])
            if per_peer[peer] >= MAX_BLOCKS_PER_PEER:
                break
            self.in_flight[block_hash] = peer
            per_peer[peer] += 1
            requested[peer].append(InventoryVector(MSG_WITNESS_BLOCK, block_hash))
            outstanding += 1
        for peer, inventory in requested.items():
            await peer.send("getdata", encode_inventory(inventory))
        await self._activate_if_ready()
        return sum(len(items) for items in requested.values())

    async def handle(self, peer: PeerConnection, message: Message, peers: list[PeerConnection]) -> bool:
        """Serve block requests or connect a downloaded block."""
        if message.command == "getdata":
            try:
                inventory = decode_inventory(message.payload)
            except ValueError:
                await peer.close()
                raise
            missing = []
            for item in inventory:
                if item.type & 0x3FFFFFFF != 2:
                    missing.append(item)
                    continue
                block = self.store.load_block(item.hash)
                if block is None:
                    missing.append(item)
                else:
                    await peer.send("block", block.serialize())
            if missing:
                await peer.send("notfound", encode_inventory(missing))
            return True
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
        index = self.headers.indexes[block_hash]
        self.store.save_block(block, index)
        await self._activate_if_ready()
        await self.request_more(peers)
        return True

    def handle_notfound(self, peer: PeerConnection, payload: bytes) -> tuple[bytes, ...]:
        """Release block requests the peer reports it cannot fulfill."""
        unavailable = []
        for item in decode_inventory(payload):
            block_hash = item.hash
            if item.type & 0x3FFFFFFF == 2 and self.in_flight.get(block_hash) is peer:
                del self.in_flight[block_hash]
                unavailable.append(block_hash)
        return tuple(unavailable)

    def _branches(self) -> tuple[BlockIndex | None, list[BlockIndex], list[BlockIndex]] | None:
        """Return the fork, active branch to disconnect, and best branch to add."""
        target = self.headers.tip
        if target is None:
            return None
        active_hash = self.store.best_block()
        active = self.headers.indexes.get(active_hash) if active_hash is not None else None
        if active_hash is not None and active is None:
            raise BlockConnectionError("active block is missing from the header index")
        if active is not None and target.chainwork <= active.chainwork:
            return None
        left, right = active, target
        while left is not None and right is not None and left.height > right.height:
            left = left.previous
        while left is not None and right is not None and right.height > left.height:
            right = right.previous
        while left is not right:
            left = left.previous if left is not None else None
            right = right.previous if right is not None else None
        fork = left
        old_branch = []
        cursor = active
        while cursor is not fork and cursor is not None:
            old_branch.append(cursor)
            cursor = cursor.previous
        new_branch = []
        cursor = target
        while cursor is not fork and cursor is not None:
            new_branch.append(cursor)
            cursor = cursor.previous
        new_branch.reverse()
        return fork, old_branch, new_branch

    async def _activate_if_ready(self) -> bool:
        branch = self._branches()
        if branch is None:
            return False
        _fork, old_branch, new_branch = branch
        blocks = []
        for index in new_branch:
            pending = self.pending.get(index.block_hash)
            block = pending[0] if pending is not None else self.store.load_block(index.block_hash)
            if block is None:
                return False
            blocks.append(block)
        if not blocks:
            return False
        try:
            self.store.reorganize(
                self.coins,
                tuple(index.block_hash for index in old_branch),
                tuple(blocks),
                tuple(new_branch),
                self.params,
                input_verifier=self.input_verifier,
                check_pow=self.check_pow,
            )
        except (ValueError, BlockConnectionError):
            self.store.discard_side_blocks(tuple(index.block_hash for index in new_branch))
            for index in new_branch:
                pending = self.pending.pop(index.block_hash, None)
                self.in_flight.pop(index.block_hash, None)
                if pending is not None:
                    await pending[1].close()
            return False
        for index in new_branch:
            self.pending.pop(index.block_hash, None)
        return True

    def peer_disconnected(self, peer: PeerConnection) -> tuple[bytes, ...]:
        """Release pending requests assigned to a disconnected peer."""
        abandoned = tuple(block_hash for block_hash, assigned in self.in_flight.items() if assigned is peer)
        for block_hash in abandoned:
            del self.in_flight[block_hash]
        return abandoned
