"""In-memory transaction mempool with dependency and conflict tracking."""

from __future__ import annotations

import heapq
import time
from dataclasses import dataclass, field
from fractions import Fraction

from bitcoin_core.consensus.chainstate import Coin, CoinsView, InputVerifier
from bitcoin_core.primitives.transaction import MAX_MONEY, OutPoint, Transaction
from bitcoin_core.policy.standard import check_standard_inputs, check_standard_transaction
from bitcoin_core.script.sigops import input_sigop_cost, legacy_sigop_cost

COINBASE_MATURITY = 100
MSG_TX = 1
MSG_WTX = 5
MAX_REPLACEMENT_CANDIDATES = 100
RBF_SEQUENCE_THRESHOLD = 0xFFFFFFFE
BYTES_PER_SIGOP = 20


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
    height: int = 0
    weight: int = 0
    vsize_bip141: int = 0
    sigop_cost: int = 0
    fee_delta: int = 0

    @property
    def txid(self) -> bytes:
        return self.transaction.txid

    @property
    def wtxid(self) -> bytes:
        return self.transaction.wtxid

    @property
    def modified_fee(self) -> int:
        """Return the saturated mining-policy fee, distinct from paid fee."""
        return max(-(1 << 63), min((1 << 63) - 1, self.fee + self.fee_delta))


@dataclass(slots=True)
class Mempool:
    """Policy-filtered unconfirmed transactions indexed by txid and spent outpoint."""

    max_vbytes: int = 300_000_000
    min_relay_fee_per_kvb: int = 100
    permit_bare_multisig: bool = True
    max_datacarrier_bytes: int = 100_000
    entries: dict[bytes, MempoolEntry] = field(default_factory=dict)
    spent_outpoints: dict[tuple[bytes, int], bytes] = field(default_factory=dict)
    unbroadcast_txs: set[bytes] = field(default_factory=set)
    fee_deltas: dict[bytes, int] = field(default_factory=dict)
    total_vbytes: int = 0
    sequence: int = 1
    transactions_updated: int = 1

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
        standardness = check_standard_transaction(
            tx,
            permit_bare_multisig=self.permit_bare_multisig,
            max_datacarrier_bytes=self.max_datacarrier_bytes,
        )
        if not standardness.standard:
            raise MempoolError(f"non-standard transaction: {standardness.reason}")
        consensus_params = getattr(input_verifier, "params", None)
        csv_height = getattr(consensus_params, "csv_height", None)
        csv_active = (
            True if consensus_params is None else csv_height is not None and height >= csv_height
        )
        if tx.lock_time:
            lock_time_cutoff = height if tx.lock_time < 500_000_000 else (
                median_time_past if csv_active else int(time.time())
            )
            if lock_time_cutoff is None:
                raise MempoolError("median-time-past is required for time-based locktime")
            if tx.lock_time >= lock_time_cutoff and any(txin.sequence != 0xFFFFFFFF for txin in tx.inputs):
                raise MempoolError("transaction is non-final at the current chain tip")

        prevouts: list[Coin] = []
        parents: set[bytes] = set()
        seen: set[tuple[bytes, int]] = set()
        input_value = 0
        direct_conflicts = {
            self.spent_outpoints[key]
            for txin in tx.inputs
            if (key := (txin.previous_output.txid, txin.previous_output.index)) in self.spent_outpoints
        }
        replacements = self._replacement_set(direct_conflicts)
        for input_index, txin in enumerate(tx.inputs):
            key = (txin.previous_output.txid, txin.previous_output.index)
            if key in seen:
                raise MempoolError("transaction contains duplicate inputs")
            seen.add(key)
            coin = chain_coins.coins.get(key)
            if coin is None:
                parent = self.entries.get(txin.previous_output.txid)
                if parent is None or txin.previous_output.index >= len(parent.transaction.outputs):
                    raise MempoolError("transaction input is missing or spent")
                txout = parent.transaction.outputs[txin.previous_output.index]
                coin = Coin(
                    txout.value,
                    txout.script_pubkey,
                    height,
                    False,
                    median_time_past if median_time_past is not None else 0,
                )
                parents.add(parent.txid)
            if coin.coinbase and height - coin.height < COINBASE_MATURITY:
                raise MempoolError("transaction spends an immature coinbase output")
            input_value += coin.value
            if input_value > MAX_MONEY:
                raise MempoolError("transaction input value out of range")
            prevouts.append(coin)
        input_standardness = check_standard_inputs(tx, tuple(prevouts))
        if not input_standardness.standard:
            raise MempoolError(f"non-standard inputs: {input_standardness.reason}")
        if tx.version >= 2 and csv_active:
            for txin, coin in zip(tx.inputs, prevouts):
                sequence = txin.sequence
                if sequence & (1 << 31):
                    continue
                relative = sequence & 0x0000FFFF
                if sequence & (1 << 22):
                    if median_time_past is None:
                        raise MempoolError("median-time-past is required for relative time locks")
                    minimum_time = coin.median_time_past + (relative << 9) - 1
                    if minimum_time >= median_time_past:
                        raise MempoolError("transaction sequence time lock is not satisfied")
                elif coin.height + relative - 1 >= height:
                    raise MempoolError("transaction sequence height lock is not satisfied")
        for input_index, coin in enumerate(prevouts):
            contextual_verifier = getattr(input_verifier, "verify_at_height", None)
            if contextual_verifier is not None:
                verified = contextual_verifier(tx, input_index, coin, tuple(prevouts), height)
            else:
                verified = input_verifier(tx, input_index, coin, tuple(prevouts))
            if not verified:
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
        vsize_bip141 = (weight + 3) // 4
        sigop_cost = legacy_sigop_cost(tx) + input_sigop_cost(tx, tuple(prevouts))
        vsize = max(vsize_bip141, (sigop_cost * BYTES_PER_SIGOP + 3) // 4)
        minimum_fee = self._fee_for_rate(vsize, self.min_relay_fee_per_kvb)
        fee_delta = self.fee_deltas.get(txid, 0)
        modified_fee = max(-(1 << 63), min((1 << 63) - 1, fee + fee_delta))
        if modified_fee < minimum_fee:
            raise MempoolError("transaction fee is below the minimum relay fee")

        if direct_conflicts:
            if len(replacements) > MAX_REPLACEMENT_CANDIDATES:
                raise MempoolError("replacement would evict more than 100 transactions")
            if not all(self._signals_replaceable(conflict_id) for conflict_id in direct_conflicts):
                raise MempoolError("conflicting transaction did not signal replaceability")
            original_inputs = {
                txin.previous_output.txid
                for conflict_id in replacements
                for txin in self.entries[conflict_id].transaction.inputs
            }
            if any(
                txin.previous_output.txid in self.entries
                and txin.previous_output.txid not in original_inputs
                for txin in tx.inputs
            ):
                raise MempoolError("replacement adds a new unconfirmed input")
            replaced_fee = sum(self.entries[item].fee for item in replacements)
            incremental_fee = self._fee_for_rate(vsize, self.min_relay_fee_per_kvb)
            if fee < replaced_fee + incremental_fee:
                raise MempoolError("replacement fee does not pay for the conflicts and incremental relay fee")
            if any(
                Fraction(fee, vsize) <= Fraction(self.entries[item].fee, self.entries[item].vsize)
                for item in direct_conflicts
            ):
                raise MempoolError("replacement feerate must exceed every direct conflict")

        for conflict_id in sorted(replacements):
            self.remove(conflict_id, recursive=True)
            self.clear_prioritisation(conflict_id)

        entry = MempoolEntry(
            tx,
            fee,
            vsize,
            int(time.time()) if now is None else now,
            parents,
            height=height,
            weight=weight,
            vsize_bip141=vsize_bip141,
            sigop_cost=sigop_cost,
            fee_delta=fee_delta,
        )
        self.entries[txid] = entry
        self.sequence += 1
        self.transactions_updated += 1
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
            self.sequence += 1
            self.transactions_updated += 1
            self.unbroadcast_txs.discard(current)
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
            self.clear_prioritisation(tx.txid)
        for tx in transactions:
            for txin in tx.inputs:
                spender = self.spent_outpoints.get((txin.previous_output.txid, txin.previous_output.index))
                if spender is not None and spender not in included:
                    removed.extend(self.remove(spender, recursive=True))
                    self.clear_prioritisation(spender)
        return tuple(dict.fromkeys(removed))

    def prioritise(self, txid: bytes, fee_delta: int) -> int:
        """Adjust a transaction's mining score without changing its actual fee."""
        if len(txid) != 32 or not -(1 << 63) <= fee_delta < (1 << 63):
            raise ValueError("transaction fee delta must fit int64")
        current = self.fee_deltas.get(txid, 0)
        updated = max(-(1 << 63), min((1 << 63) - 1, current + fee_delta))
        if updated:
            self.fee_deltas[txid] = updated
        else:
            self.fee_deltas.pop(txid, None)
        if updated != current:
            self.transactions_updated += 1
        entry = self.entries.get(txid)
        if entry is not None:
            entry.fee_delta = updated
        return updated

    def clear_prioritisation(self, txid: bytes) -> None:
        """Clear a transaction's fee delta when it confirms or conflicts."""
        previous_delta = self.fee_deltas.pop(txid, 0)
        entry = self.entries.get(txid)
        if entry is not None:
            previous_delta = entry.fee_delta or previous_delta
            entry.fee_delta = 0
        if previous_delta:
            self.transactions_updated += 1

    def clear(self) -> None:
        """Remove all mempool entries and dependency indexes."""
        self.sequence += len(self.entries)
        self.transactions_updated += len(self.entries)
        self.entries.clear()
        self.spent_outpoints.clear()
        self.unbroadcast_txs.clear()
        self.fee_deltas.clear()
        self.total_vbytes = 0

    def revalidate(
        self,
        chain_coins: CoinsView,
        height: int,
        *,
        input_verifier: InputVerifier,
        median_time_past: int | None = None,
    ) -> tuple[bytes, ...]:
        """Rebuild the pool in dependency order against a changed active chain."""
        previous = self.entries.copy()
        candidates = {txid: entry.transaction for txid, entry in previous.items()}
        priorities = self.fee_deltas.copy()
        unbroadcast = self.unbroadcast_txs.copy()

        children: dict[bytes, set[bytes]] = {txid: set() for txid in candidates}
        indegree = {txid: 0 for txid in candidates}
        for txid, tx in candidates.items():
            parents = {
                txin.previous_output.txid
                for txin in tx.inputs
                if txin.previous_output.txid in candidates and txin.previous_output.txid != txid
            }
            indegree[txid] = len(parents)
            for parent in parents:
                children[parent].add(txid)

        self.entries.clear()
        self.spent_outpoints.clear()
        self.total_vbytes = 0
        self.fee_deltas = priorities
        self.unbroadcast_txs = unbroadcast
        ready = [
            (previous[txid].added_at, txid)
            for txid, degree in indegree.items()
            if degree == 0
        ]
        heapq.heapify(ready)
        while ready:
            _added_at, txid = heapq.heappop(ready)
            try:
                self.accept(
                    candidates[txid],
                    chain_coins,
                    height,
                    input_verifier=input_verifier,
                    median_time_past=median_time_past,
                    now=previous[txid].added_at,
                )
            except MempoolError:
                pass
            for child in children[txid]:
                indegree[child] -= 1
                if indegree[child] == 0:
                    heapq.heappush(ready, (previous[child].added_at, child))
        # A cyclic dependency is invalid; any descendants of a rejected parent
        # have already been reconsidered and rejected for their missing input.
        removed = tuple(txid for txid in candidates if txid not in self.entries)
        self.unbroadcast_txs.intersection_update(self.entries)
        return removed

    def _trim_to_size(self) -> None:
        while self.total_vbytes > self.max_vbytes and self.entries:
            lowest = min(
                self.entries.values(),
                key=lambda entry: (Fraction(entry.modified_fee, entry.vsize), entry.added_at, entry.txid),
            )
            self.remove(lowest.txid, recursive=True)

    def _signals_replaceable(self, txid: bytes, seen: set[bytes] | None = None) -> bool:
        entry = self.entries.get(txid)
        if entry is None:
            return False
        if any(txin.sequence < RBF_SEQUENCE_THRESHOLD for txin in entry.transaction.inputs):
            return True
        visited = set() if seen is None else seen
        if txid in visited:
            return False
        visited.add(txid)
        return any(self._signals_replaceable(parent, visited) for parent in entry.parents)

    def _replacement_set(self, direct_conflicts: set[bytes]) -> set[bytes]:
        replacements = set(direct_conflicts)
        pending = list(direct_conflicts)
        while pending:
            current = pending.pop()
            entry = self.entries.get(current)
            if entry is None:
                continue
            for child in entry.children:
                if child not in replacements:
                    replacements.add(child)
                    pending.append(child)
        return replacements

    @staticmethod
    def _fee_for_rate(vsize: int, satoshis_per_kvb: int) -> int:
        fee = vsize * satoshis_per_kvb // 1_000
        return max(1, fee) if vsize and satoshis_per_kvb > 0 else fee
