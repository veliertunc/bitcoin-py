"""Bounded storage for transactions waiting on unconfirmed parent transactions."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.primitives.transaction import Transaction

MAX_ORPHAN_TRANSACTION_SIZE = 100_000
MAX_ORPHANAGE_BYTES = 20_000_000
ORPHAN_EXPIRY_SECONDS = 20 * 60


@dataclass(frozen=True, slots=True)
class OrphanTransaction:
    """A transaction and the peer that announced it while parents were absent."""

    transaction: Transaction
    missing_parents: frozenset[bytes]
    peer: PeerConnection | None
    added_at: int
    size: int

    @property
    def txid(self) -> bytes:
        return self.transaction.txid


@dataclass(slots=True)
class Orphanage:
    """Index orphan transactions by txid and every missing parent txid."""

    max_bytes: int = MAX_ORPHANAGE_BYTES
    expiry_seconds: int = ORPHAN_EXPIRY_SECONDS
    entries: dict[bytes, OrphanTransaction] = field(default_factory=dict)
    by_parent: dict[bytes, set[bytes]] = field(default_factory=dict)
    total_bytes: int = 0

    def add(
        self,
        transaction: Transaction,
        missing_parents: set[bytes] | frozenset[bytes],
        peer: PeerConnection | None,
        *,
        now: int | None = None,
    ) -> bool:
        """Store a bounded orphan, evicting oldest entries to make space."""
        self.prune(now=now)
        txid = transaction.txid
        size = len(transaction.serialize(include_witness=True))
        parents = frozenset(missing_parents)
        if (
            txid in self.entries
            or not parents
            or any(len(parent) != 32 for parent in parents)
            or size > MAX_ORPHAN_TRANSACTION_SIZE
            or size > self.max_bytes
        ):
            return False
        added_at = int(time.time()) if now is None else now
        while self.total_bytes + size > self.max_bytes and self.entries:
            oldest = min(self.entries.values(), key=lambda item: (item.added_at, item.txid))
            self.remove(oldest.txid)
        entry = OrphanTransaction(transaction, parents, peer, added_at, size)
        self.entries[txid] = entry
        self.total_bytes += size
        for parent in parents:
            self.by_parent.setdefault(parent, set()).add(txid)
        return True

    def remove(self, txid: bytes) -> OrphanTransaction | None:
        """Remove one orphan and all parent indexes pointing to it."""
        entry = self.entries.pop(txid, None)
        if entry is None:
            return None
        self.total_bytes -= entry.size
        for parent in entry.missing_parents:
            children = self.by_parent.get(parent)
            if children is None:
                continue
            children.discard(txid)
            if not children:
                self.by_parent.pop(parent, None)
        return entry

    def children_of(self, parent_txid: bytes) -> tuple[bytes, ...]:
        """Return waiting txids that reference a newly available parent."""
        return tuple(sorted(self.by_parent.get(parent_txid, ())))

    def prune(self, *, now: int | None = None) -> tuple[bytes, ...]:
        """Drop orphans that have exceeded the network retention period."""
        timestamp = int(time.time()) if now is None else now
        expired = [
            txid for txid, entry in self.entries.items()
            if timestamp - entry.added_at >= self.expiry_seconds
        ]
        for txid in expired:
            self.remove(txid)
        return tuple(expired)
