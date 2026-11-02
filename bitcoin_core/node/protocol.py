"""Dispatch established peer messages to header and block synchronization."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field

from bitcoin_core.network.addrman import AddressBook
from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.network.compact_filters import (
    BASIC_FILTER_TYPE,
    CF_CHECKPT_INTERVAL,
    MAX_GETCFILTERS,
    MAX_GETCFHEADERS,
    decode_filter_checkpoints,
    decode_filter_range,
    encode_cfcheckpt,
    encode_cfheaders,
    encode_cfilter,
)
from bitcoin_core.crypto.hashes import hash256
from bitcoin_core.network.messages import (
    GetBlocks,
    TimestampedAddress,
    decode_addr,
    decode_inventory,
    encode_addr,
    encode_headers,
    encode_inventory,
    InventoryVector,
    MAX_HEADERS,
)
from bitcoin_core.network.protocol import Message
from bitcoin_core.network.version import NetworkAddress
from bitcoin_core.node.block_sync import BlockSynchronizer
from bitcoin_core.node.mempool import MempoolError
from bitcoin_core.node.relay import MempoolRelay
from bitcoin_core.node.sync import HeaderSynchronizer

MAX_GETBLOCKS_RESULTS = 500
MSG_BLOCK = 2


@dataclass(slots=True)
class NodeProtocol:
    """Compose peer handshake, header sync, and block sync message handling."""

    headers: HeaderSynchronizer
    blocks: BlockSynchronizer
    peers: Callable[[], list[PeerConnection]]
    relay: MempoolRelay | None = None
    address_book: AddressBook | None = None
    pending_header_requests: dict[PeerConnection, bytes] = field(default_factory=dict)

    async def __call__(self, peer: PeerConnection, message: Message) -> None:
        if message.command == "verack":
            if peer.established:
                if self.address_book is not None and peer.address is not None and peer.handshake.remote_version:
                    try:
                        remote_ip = ipaddress.ip_address(peer.address[0])
                        self.address_book.mark_success(
                            NetworkAddress(
                                peer.handshake.remote_version.services,
                                remote_ip,
                                peer.address[1],
                            )
                        )
                    except (ValueError, IndexError):
                        pass
                await self.headers.begin(peer)
                await peer.send("sendheaders")
                if self.address_book is not None:
                    await peer.send("getaddr")
                if self.relay is not None and peer.handshake.remote_version:
                    if peer.handshake.remote_version.protocol_version >= 70_013:
                        await peer.send(
                            "feefilter",
                            self.relay.mempool.min_relay_fee_per_kvb.to_bytes(8, "little"),
                        )
                await self.blocks.request_more(self.peers())
        elif message.command == "feefilter":
            if len(message.payload) != 8:
                await peer.close()
                raise ValueError("malformed feefilter message")
            peer.fee_filter = int.from_bytes(message.payload, "little")
        elif message.command == "sendheaders":
            if message.payload:
                await peer.close()
                raise ValueError("sendheaders message must be empty")
            peer.prefers_headers = True
        elif message.command == "mempool" and self.relay is not None:
            if message.payload:
                await peer.close()
                raise ValueError("mempool message must be empty")
            await self.relay.serve_mempool(peer)
        elif message.command == "addr" and self.address_book is not None:
            try:
                addresses = decode_addr(message.payload)
            except ValueError:
                await peer.close()
                raise
            source = str(peer.address[0]) if peer.address else ""
            self.address_book.add_many(addresses, source=source)
        elif message.command == "getaddr" and self.address_book is not None:
            entries = tuple(
                TimestampedAddress(record.timestamp, record.address)
                for record in self.address_book.recent()
            )
            await peer.send("addr", encode_addr(entries))
        elif message.command == "getheaders":
            await peer.send("headers", self.headers.serve_getheaders(message.payload))
        elif message.command == "getblocks":
            try:
                request = GetBlocks.deserialize(message.payload)
            except ValueError:
                await peer.close()
                raise
            store = self.blocks.store
            fork_height = 0
            for block_hash in request.locators:
                candidate = self.headers.chain.indexes.get(block_hash)
                if (
                    candidate is not None
                    and store.active_block_hash(candidate.height) == block_hash
                ):
                    fork_height = candidate.height
                    break
            inventory = []
            best_height = store.best_height()
            for height in range(fork_height + 1, min(best_height + 1, fork_height + 1 + MAX_GETBLOCKS_RESULTS)):
                block_hash = store.active_block_hash(height)
                if block_hash is None:
                    break
                inventory.append(InventoryVector(MSG_BLOCK, block_hash))
                if block_hash == request.stop_hash:
                    break
            if inventory:
                await peer.send("inv", encode_inventory(inventory))
        elif message.command == "headers":
            old_tip = self.blocks.store.best_block()
            try:
                count = await self.headers.handle(peer, message)
            except ValueError:
                self.pending_header_requests.pop(peer, None)
                raise
            if count < MAX_HEADERS:
                self.pending_header_requests.pop(peer, None)
            await self.blocks.request_more(self.peers())
            await self._reconcile_tip(old_tip, peer)
        elif message.command == "block":
            old_tip = self.blocks.store.best_block()
            await self.blocks.handle(peer, message, self.peers())
            await self._reconcile_tip(old_tip, peer)
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
        elif message.command == "inv":
            try:
                inventory = decode_inventory(message.payload)
            except ValueError:
                await peer.close()
                raise
            block_announcements = [
                item for item in inventory if item.type & 0x3FFFFFFF == 2
            ]
            unknown_headers = [
                item.hash
                for item in block_announcements
                if item.hash not in self.headers.chain.indexes
            ]
            if unknown_headers and peer not in self.pending_header_requests:
                stop_hash = unknown_headers[-1]
                self.pending_header_requests[peer] = stop_hash
                try:
                    await self.headers.begin_until(peer, stop_hash)
                except (ConnectionError, OSError):
                    self.pending_header_requests.pop(peer, None)
            if block_announcements:
                await self.blocks.request_more(self.peers())
            if self.relay is not None:
                await self.relay.handle(peer, message, self.peers())
        elif message.command == "tx" and self.relay is not None:
            await self.relay.handle(peer, message, self.peers())
        elif message.command == "notfound":
            self.blocks.handle_notfound(peer, message.payload)
        elif message.command in ("getcfilters", "getcfheaders", "getcfcheckpt"):
            await self._serve_compact_filter_request(peer, message)

    async def _serve_compact_filter_request(self, peer: PeerConnection, message: Message) -> None:
        store = self.blocks.store
        try:
            if message.command == "getcfcheckpt":
                filter_type, stop_hash = decode_filter_checkpoints(message.payload)
                start_height = 0
            else:
                filter_type, start_height, stop_hash = decode_filter_range(message.payload)
        except ValueError:
            await peer.close()
            return

        stop_height = store.header_height(stop_hash)
        if (
            filter_type != BASIC_FILTER_TYPE
            or stop_height is None
            or store.active_block_hash(stop_height) != stop_hash
        ):
            await peer.close()
            return
        if message.command == "getcfcheckpt":
            checkpoints = []
            for height in range(CF_CHECKPT_INTERVAL, stop_height + 1, CF_CHECKPT_INTERVAL):
                block_hash = store.active_block_hash(height)
                indexed = store.load_basic_filter(block_hash) if block_hash is not None else None
                if indexed is None:
                    return
                checkpoints.append(indexed[1])
            await peer.send("cfcheckpt", encode_cfcheckpt(filter_type, stop_hash, checkpoints))
            return

        limit = MAX_GETCFILTERS if message.command == "getcfilters" else MAX_GETCFHEADERS
        if start_height > stop_height or stop_height - start_height >= limit:
            await peer.close()
            return
        hashes: list[bytes] = []
        filter_data: list[tuple[bytes, bytes]] = []
        for height in range(start_height, stop_height + 1):
            block_hash = store.active_block_hash(height)
            indexed = store.load_basic_filter(block_hash) if block_hash is not None else None
            if block_hash is None or indexed is None:
                return
            hashes.append(block_hash)
            filter_data.append(indexed)

        if message.command == "getcfilters":
            for block_hash, (encoded_filter, _header) in zip(hashes, filter_data):
                await peer.send("cfilter", encode_cfilter(filter_type, block_hash, encoded_filter))
            return

        previous_header = bytes(32)
        if start_height:
            previous_hash = store.active_block_hash(start_height - 1)
            previous = store.load_basic_filter(previous_hash) if previous_hash is not None else None
            if previous is None:
                return
            previous_header = previous[1]
        filter_hashes = [hash256(encoded_filter) for encoded_filter, _header in filter_data]
        await peer.send(
            "cfheaders",
            encode_cfheaders(filter_type, stop_hash, previous_header, filter_hashes),
        )

    async def _reconcile_tip(self, old_hash: bytes | None, source: PeerConnection) -> None:
        """Update mempool state and announce a newly activated chain tip."""
        new_hash = self.blocks.store.best_block()
        if new_hash is None or new_hash == old_hash:
            return
        new_index = self.headers.chain.indexes.get(new_hash)
        if new_index is None:
            return
        # The node's activation callback reconciles the pool for both local and
        # peer-supplied blocks. Keep this fallback for protocol users that wire
        # a synchronizer without an activation callback.
        if self.relay is not None and self.blocks.activation_handler is None:
            chain = self.headers.chain
            old_index = chain.indexes.get(old_hash) if old_hash is not None else None
            left, right = old_index, new_index
            while left is not None and right is not None and left.height > right.height:
                left = left.previous
            while left is not None and right is not None and right.height > left.height:
                right = right.previous
            while left is not right:
                left = left.previous if left is not None else None
                right = right.previous if right is not None else None
            fork = left
            disconnected = []
            cursor = old_index
            while cursor is not fork and cursor is not None:
                block = self.blocks.store.load_block(cursor.block_hash)
                if block is not None:
                    disconnected.append(block)
                cursor = cursor.previous
            disconnected.reverse()
            included_txids: set[bytes] = set()
            for height in range((fork.height + 1) if fork is not None else 0, new_index.height + 1):
                block_hash = self.blocks.store.active_block_hash(height)
                block = self.blocks.store.load_block(block_hash) if block_hash is not None else None
                if block is None:
                    continue
                included_txids.update(tx.txid for tx in block.transactions)
                self.relay.mempool.remove_for_block(block.transactions)
            for block in disconnected:
                for transaction in block.transactions[1:]:
                    if transaction.txid in included_txids:
                        continue
                    try:
                        await self.relay.submit(transaction, self.peers())
                    except MempoolError:
                        continue

        for candidate in self.peers():
            if not candidate.established or candidate is source:
                continue
            try:
                if candidate.prefers_headers:
                    await candidate.send("headers", encode_headers((new_index.header,)))
                else:
                    await candidate.send("inv", encode_inventory([InventoryVector(2, new_hash)]))
            except (ConnectionError, OSError):
                continue
