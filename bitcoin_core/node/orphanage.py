"""Bounded storage for transactions waiting on unconfirmed parent transactions."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.primitives.transaction import Transaction

MAX_ORPHAN_TRANSACTION_SIZE = 100_000
MAX_ORPHANAGE_BYTES = 20_000_000
ORPHAN_EXPIRY_SECONDS = 20 * 60
MAX_ORPHANS_PER_PEER = 100


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
    max_per_peer: int = MAX_ORPHANS_PER_PEER
    entries: dict[bytes, OrphanTransaction] = field(default_factory=dict)
    by_parent: dict[bytes, set[bytes]] = field(default_factory=dict)
    by_peer: dict[PeerConnection, set[bytes]] = field(default_factory=dict)
    total_bytes: int = 0

    def __post_init__(self) -> None:
        if self.max_bytes < 0 or self.expiry_seconds < 0 or self.max_per_peer < 0:
            raise ValueError("orphanage limits cannot be negative")

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
            or (peer is not None and self.max_per_peer == 0)
        ):
            return False
        added_at = int(time.time()) if now is None else now
        if peer is not None:
            peer_orphans = self.by_peer.get(peer, set())
            while len(peer_orphans) >= self.max_per_peer:
                oldest_peer_orphan = min(
                    (self.entries[item] for item in peer_orphans),
                    key=lambda item: (item.added_at, item.txid),
                )
                self.remove(oldest_peer_orphan.txid)
                peer_orphans = self.by_peer.get(peer, set())
        while self.total_bytes + size > self.max_bytes and self.entries:
            oldest = min(self.entries.values(), key=lambda item: (item.added_at, item.txid))
            self.remove(oldest.txid)
        entry = OrphanTransaction(transaction, parents, peer, added_at, size)
        self.entries[txid] = entry
        self.total_bytes += size
        for parent in parents:
            self.by_parent.setdefault(parent, set()).add(txid)
        if peer is not None:
            self.by_peer.setdefault(peer, set()).add(txid)
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
        if entry.peer is not None:
            peer_orphans = self.by_peer.get(entry.peer)
            if peer_orphans is not None:
                peer_orphans.discard(txid)
                if not peer_orphans:
                    self.by_peer.pop(entry.peer, None)
        return entry

    def remove_peer(self, peer: PeerConnection) -> tuple[bytes, ...]:
        """Discard orphans from a disconnected peer and release its reference."""
        txids = tuple(sorted(self.by_peer.get(peer, ())))
        for txid in txids:
            self.remove(txid)
        return txids

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
