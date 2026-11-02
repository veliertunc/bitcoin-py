"""P2P transaction relay backed by the local mempool."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from bitcoin_core.consensus.chainstate import CoinsView, InputVerifier
from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.network.messages import InventoryVector, decode_inventory, encode_inventory
from bitcoin_core.network.protocol import Message
from bitcoin_core.node.mempool import MSG_TX, MSG_WTX, Mempool, MempoolError
from bitcoin_core.node.mempool import MempoolEntry
from bitcoin_core.primitives.transaction import Transaction


@dataclass(slots=True)
class MempoolRelay:
    """Admit peer transactions, announce accepted entries, and serve getdata."""

    mempool: Mempool
    coins: Callable[[], CoinsView]
    height: Callable[[], int]
    median_time_past: Callable[[], int]
    input_verifier: InputVerifier

    async def submit(self, tx: Transaction, peers: list[PeerConnection]) -> MempoolEntry:
        """Admit a local transaction and announce its txid to connected peers."""
        entry = self.mempool.accept(
            tx,
            self.coins(),
            self.height(),
            input_verifier=self.input_verifier,
            median_time_past=self.median_time_past(),
        )
        inventory = encode_inventory([InventoryVector(MSG_TX, entry.txid)])
        for candidate in peers:
            if candidate.established:
                await candidate.send("inv", inventory)
        return entry

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
