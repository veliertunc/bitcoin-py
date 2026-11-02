"""In-memory transaction mempool with dependency and conflict tracking."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from fractions import Fraction

from bitcoin_core.consensus.chainstate import Coin, CoinsView, InputVerifier
from bitcoin_core.primitives.transaction import MAX_MONEY, OutPoint, Transaction

COINBASE_MATURITY = 100
MSG_TX = 1
MSG_WTX = 5


class MempoolError(ValueError):
    """Raised when a transaction fails mempool admission policy."""


@dataclass(slots=True)
class MempoolEntry:
    transaction: Transaction
    fee: int
    vsize: int
    added_at: int
    parents: set[bytes] = field(default_factory=set)
    children: set[bytes] = field(default_factory=set)

    @property
    def txid(self) -> bytes:
        return self.transaction.txid

    @property
    def wtxid(self) -> bytes:
        return self.transaction.wtxid


@dataclass(slots=True)
class Mempool:
    """Policy-filtered unconfirmed transactions indexed by txid and spent outpoint."""

    max_vbytes: int = 300_000_000
    min_relay_fee_per_kvb: int = 1_000
    entries: dict[bytes, MempoolEntry] = field(default_factory=dict)
    spent_outpoints: dict[tuple[bytes, int], bytes] = field(default_factory=dict)
    total_vbytes: int = 0

    def __post_init__(self) -> None:
        if self.max_vbytes < 0 or self.min_relay_fee_per_kvb < 0:
            raise ValueError("mempool size and relay fee limits cannot be negative")

    def get(self, txid: bytes) -> Transaction | None:
        entry = self.entries.get(txid)
        return None if entry is None else entry.transaction

    def get_by_wtxid(self, wtxid: bytes) -> Transaction | None:
        return next((entry.transaction for entry in self.entries.values() if entry.wtxid == wtxid), None)

    def accept(
        self,
        tx: Transaction,
        chain_coins: CoinsView,
        height: int,
        *,
        input_verifier: InputVerifier,
        median_time_past: int | None = None,
        now: int | None = None,
    ) -> MempoolEntry:
        """Validate and insert one transaction, rejecting conflicts and low fees."""
        txid = tx.txid
        if txid in self.entries:
            raise MempoolError("transaction is already in the mempool")
        if not tx.inputs or not tx.outputs:
            raise MempoolError("transaction must contain inputs and outputs")
        if any(txin.previous_output.is_null for txin in tx.inputs):
            raise MempoolError("coinbase transactions are not accepted into the mempool")
        if tx.nLockTime:
            lock_time_cutoff = height if tx.nLockTime < 500_000_000 else median_time_past
            if lock_time_cutoff is None:
                raise MempoolError("median-time-past is required for time-based locktime")
            if tx.nLockTime >= lock_time_cutoff and any(txin.sequence != 0xFFFFFFFF for txin in tx.inputs):
                raise MempoolError("transaction is non-final at the current chain tip")

        prevouts: list[Coin] = []
        parents: set[bytes] = set()
        seen: set[tuple[bytes, int]] = set()
        input_value = 0
        for input_index, txin in enumerate(tx.inputs):
            key = (txin.previous_output.txid, txin.previous_output.index)
            if key in seen:
                raise MempoolError("transaction contains duplicate inputs")
            seen.add(key)
            if key in self.spent_outpoints:
                raise MempoolError("transaction conflicts with a mempool spend")
            coin = chain_coins.coins.get(key)
            if coin is None:
                parent = self.entries.get(txin.previous_output.txid)
                if parent is None or txin.previous_output.index >= len(parent.transaction.outputs):
                    raise MempoolError("transaction input is missing or spent")
                txout = parent.transaction.outputs[txin.previous_output.index]
                coin = Coin(txout.value, txout.script_pubkey, height, False)
                parents.add(parent.txid)
            if coin.coinbase and height - coin.height < COINBASE_MATURITY:
                raise MempoolError("transaction spends an immature coinbase output")
            input_value += coin.value
            if input_value > MAX_MONEY:
                raise MempoolError("transaction input value out of range")
            prevouts.append(coin)
        for input_index, coin in enumerate(prevouts):
            if not input_verifier(tx, input_index, coin, tuple(prevouts)):
                raise MempoolError("transaction input script verification failed")

        try:
            output_value = tx.output_value()
        except ValueError as exc:
            raise MempoolError(str(exc)) from exc
        if output_value > input_value:
            raise MempoolError("transaction spends more than its inputs")
        fee = input_value - output_value
        stripped_size = len(tx.serialize(include_witness=False))
        total_size = len(tx.serialize(include_witness=True))
        weight = stripped_size * 3 + total_size
        vsize = (weight + 3) // 4
        minimum_fee = (vsize * self.min_relay_fee_per_kvb + 999) // 1_000
        if fee < minimum_fee:
            raise MempoolError("transaction fee is below the minimum relay fee")

        entry = MempoolEntry(tx, fee, vsize, int(time.time()) if now is None else now, parents)
        self.entries[txid] = entry
        self.total_vbytes += vsize
        for parent_id in parents:
            self.entries[parent_id].children.add(txid)
        for txin in tx.inputs:
            self.spent_outpoints[(txin.previous_output.txid, txin.previous_output.index)] = txid
        self._trim_to_size()
        if txid not in self.entries:
            raise MempoolError("transaction evicted by mempool size limit")
        return entry

    def remove(self, txid: bytes, *, recursive: bool = True) -> tuple[bytes, ...]:
        """Remove a transaction and optionally all descendants."""
        if txid not in self.entries:
            return ()
        removal = {txid}
        if recursive:
            pending = [txid]
            while pending:
                current = pending.pop()
                for child in self.entries[current].children:
                    if child not in removal:
                        removal.add(child)
                        pending.append(child)
        removed: list[bytes] = []
        for current in removal:
            entry = self.entries.pop(current, None)
            if entry is None:
                continue
            self.total_vbytes -= entry.vsize
            removed.append(current)
            for txin in entry.transaction.inputs:
                key = (txin.previous_output.txid, txin.previous_output.index)
                if self.spent_outpoints.get(key) == current:
                    del self.spent_outpoints[key]
            for parent_id in entry.parents:
                parent = self.entries.get(parent_id)
                if parent is not None:
                    parent.children.discard(current)
            for child_id in entry.children:
                child = self.entries.get(child_id)
                if child is not None:
                    child.parents.discard(current)
        return tuple(removed)

    def remove_for_block(self, transactions: tuple[Transaction, ...] | list[Transaction]) -> tuple[bytes, ...]:
        """Remove confirmed transactions and mempool spends conflicting with the block."""
        removed: list[bytes] = []
        included = {tx.txid for tx in transactions}
        for tx in transactions:
            entry = self.entries.get(tx.txid)
            if entry is not None:
                removed.extend(self.remove(tx.txid, recursive=False))
        for tx in transactions:
            for txin in tx.inputs:
                spender = self.spent_outpoints.get((txin.previous_output.txid, txin.previous_output.index))
                if spender is not None and spender not in included:
                    removed.extend(self.remove(spender, recursive=True))
        return tuple(dict.fromkeys(removed))

    def clear(self) -> None:
        """Remove all mempool entries and dependency indexes."""
        self.entries.clear()
        self.spent_outpoints.clear()
        self.total_vbytes = 0

    def _trim_to_size(self) -> None:
        while self.total_vbytes > self.max_vbytes and self.entries:
            lowest = min(
                self.entries.values(),
                key=lambda entry: (Fraction(entry.fee, entry.vsize), entry.added_at, entry.txid),
            )
            self.remove(lowest.txid, recursive=True)
