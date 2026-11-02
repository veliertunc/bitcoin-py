"""P2P transaction relay backed by the local mempool."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from bitcoin_core.consensus.chainstate import CoinsView, InputVerifier
from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.network.messages import InventoryVector, decode_inventory, encode_inventory
from bitcoin_core.network.protocol import Message
from bitcoin_core.node.mempool import MSG_TX, MSG_WTX, Mempool, MempoolError
from bitcoin_core.node.mempool import MempoolEntry
from bitcoin_core.node.orphanage import Orphanage
from bitcoin_core.primitives.transaction import Transaction


@dataclass(slots=True)
class MempoolRelay:
    """Admit peer transactions, announce accepted entries, and serve getdata."""

    mempool: Mempool
    coins: Callable[[], CoinsView]
    height: Callable[[], int]
    median_time_past: Callable[[], int]
    input_verifier: InputVerifier
    orphanage: Orphanage = field(default_factory=Orphanage)

    async def submit(
        self,
        tx: Transaction,
        peers: list[PeerConnection],
        *,
        unbroadcast: bool = False,
    ) -> MempoolEntry:
        """Admit a local transaction and announce its txid to connected peers."""
        entry = self.mempool.accept(
            tx,
            self.coins(),
            self.height(),
            input_verifier=self.input_verifier,
            median_time_past=self.median_time_past(),
        )
        if unbroadcast:
            self.mempool.unbroadcast_txs.add(entry.txid)
        await self._announce(entry, peers)
        await self._process_orphans(entry.txid, peers)
        return entry

    async def _announce(
        self,
        entry: MempoolEntry,
        peers: list[PeerConnection],
        *,
        exclude: PeerConnection | None = None,
    ) -> None:
        for candidate in peers:
            wtxid_relay = (
                candidate.handshake.sent_wtxidrelay
                and candidate.handshake.received_wtxidrelay
            )
            if (
                candidate is not exclude
                and candidate.established
                and entry.fee * 1_000 >= candidate.fee_filter * entry.vsize
            ):
                try:
                    inventory = encode_inventory([
                        InventoryVector(
                            MSG_WTX if wtxid_relay else MSG_TX,
                            entry.wtxid if wtxid_relay else entry.txid,
                        )
                    ])
                    await candidate.send("inv", inventory)
                except (ConnectionError, OSError):
                    continue

    def _missing_parents(self, transaction: Transaction) -> set[bytes]:
        coins = self.coins().coins
        missing = set()
        for txin in transaction.inputs:
            outpoint = txin.previous_output
            if (outpoint.txid, outpoint.index) in coins or outpoint.txid in self.mempool.entries:
                continue
            missing.add(outpoint.txid)
        return missing

    async def _request_missing_parents(self, peer: PeerConnection, missing: set[bytes]) -> None:
        if not peer.established or not missing:
            return
        request = encode_inventory([InventoryVector(MSG_TX, txid) for txid in sorted(missing)])
        try:
            await peer.send("getdata", request)
        except (ConnectionError, OSError):
            return

    async def _process_orphans(self, parent_txid: bytes, peers: list[PeerConnection]) -> None:
        pending = list(self.orphanage.children_of(parent_txid))
        while pending:
            orphan_txid = pending.pop(0)
            orphan = self.orphanage.remove(orphan_txid)
            if orphan is None:
                continue
            missing = self._missing_parents(orphan.transaction)
            if missing:
                self.orphanage.add(orphan.transaction, missing, orphan.peer)
                if orphan.peer is not None:
                    await self._request_missing_parents(orphan.peer, missing)
                continue
            try:
                entry = self.mempool.accept(
                    orphan.transaction,
                    self.coins(),
                    self.height(),
                    input_verifier=self.input_verifier,
                    median_time_past=self.median_time_past(),
                )
            except MempoolError:
                # A now-known parent may have made this transaction invalid or conflicting.
                continue
            await self._announce(entry, peers, exclude=orphan.peer)
            pending.extend(self.orphanage.children_of(entry.txid))

    async def handle(self, peer: PeerConnection, message: Message, peers: list[PeerConnection]) -> bool:
        """Process tx or inv messages; return whether the message was handled."""
        if message.command == "tx":
            try:
                tx = Transaction.deserialize(message.payload)
            except (EOFError, ValueError):
                await peer.close()
                raise
            try:
                await self.submit(tx, [candidate for candidate in peers if candidate is not peer])
            except MempoolError:
                missing = self._missing_parents(tx)
                if missing and self.orphanage.add(tx, missing, peer):
                    await self._request_missing_parents(peer, missing)
                return True
            return True
        if message.command == "inv":
            try:
                announced = decode_inventory(message.payload)
            except ValueError:
                await peer.close()
                raise
            requests = []
            for item in announced:
                if item.type == MSG_TX:
                    self.mempool.unbroadcast_txs.discard(item.hash)
                elif item.type == MSG_WTX:
                    transaction = self.mempool.get_by_wtxid(item.hash)
                    if transaction is not None:
                        self.mempool.unbroadcast_txs.discard(transaction.txid)
                if item.type == MSG_TX and self.mempool.get(item.hash) is None:
                    requests.append(item)
                elif item.type == MSG_WTX and self.mempool.get_by_wtxid(item.hash) is None:
                    requests.append(item)
            if requests:
                await peer.send("getdata", encode_inventory(requests))
            return True
        return False

    async def serve_inventory(
        self,
        peer: PeerConnection,
        inventory: tuple[InventoryVector, ...] | list[InventoryVector],
    ) -> list[InventoryVector]:
        """Serve known transactions and return inventory entries still unresolved."""
        missing = []
        for item in inventory:
            if item.type == MSG_TX:
                tx = self.mempool.get(item.hash)
            elif item.type == MSG_WTX:
                tx = self.mempool.get_by_wtxid(item.hash)
            else:
                missing.append(item)
                continue
            if tx is None:
                missing.append(item)
            else:
                await peer.send("tx", tx.serialize(include_witness=True))
        return missing

    async def serve_mempool(self, peer: PeerConnection) -> int:
        """Answer a BIP35 mempool request with fee-filtered transaction inventory."""
        wtxid_relay = (
            peer.handshake.sent_wtxidrelay
            and peer.handshake.received_wtxidrelay
        )
        inventory = [
            InventoryVector(
                MSG_WTX if wtxid_relay else MSG_TX,
                entry.wtxid if wtxid_relay else entry.txid,
            )
            for entry in self.mempool.entries.values()
            if entry.fee * 1_000 >= peer.fee_filter * entry.vsize
        ]
        for start in range(0, len(inventory), 50_000):
            await peer.send("inv", encode_inventory(inventory[start : start + 50_000]))
        return len(inventory)
