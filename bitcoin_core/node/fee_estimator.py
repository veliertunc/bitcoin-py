"""Mempool health tracking and short-horizon fee estimation."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from bitcoin_core.node.mempool import Mempool

MAX_TARGET = 2
HEALTH_WINDOW_BLOCKS = 6
BLOCK_MAX_WEIGHT = 4_000_000
MIN_REPRESENTATIVE_WEIGHT = BLOCK_MAX_WEIGHT
MIN_MEMPOOL_REPRESENTATION = 0.75


@dataclass(frozen=True, slots=True)
class MinedBlockStats:
    height: int
    block_hash: bytes
    block_weight: int
    mempool_txs_weight: int


@dataclass(slots=True)
class MempoolFeeEstimator:
    """Estimate next-block feerates when recent blocks adequately sample mempool."""

    path: str | Path
    mempool: Mempool
    _db: sqlite3.Connection = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._db = sqlite3.connect(str(self.path))
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS mined_block_stats (
                height INTEGER PRIMARY KEY,
                block_hash BLOB NOT NULL CHECK(length(block_hash) = 32),
                block_weight INTEGER NOT NULL CHECK(block_weight >= 0),
                mempool_txs_weight INTEGER NOT NULL CHECK(mempool_txs_weight >= 0)
            )"""
        )
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(mined_block_stats)")}
        if "block_hash" not in columns:
            self._db.execute(
                "ALTER TABLE mined_block_stats ADD COLUMN block_hash BLOB NOT NULL "
                f"DEFAULT X'{bytes(32).hex()}'"
            )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def record_block(
        self,
        height: int,
        block_hash: bytes,
        parent_hash: bytes,
        block_weight: int,
        mempool_txs_weight: int,
    ) -> None:
        """Record one active-chain block and discard observations made stale by a reorg."""
        if (
            height < 0
            or len(block_hash) != 32
            or len(parent_hash) != 32
            or block_weight < 0
            or mempool_txs_weight < 0
        ):
            raise ValueError("fee estimator block statistics are malformed")
        with self._db:
            self._db.execute("DELETE FROM mined_block_stats WHERE height >= ?", (height,))
            previous = self._db.execute(
                "SELECT height, block_hash FROM mined_block_stats ORDER BY height DESC LIMIT 1"
            ).fetchone()
            if previous is not None and (previous[0] != height - 1 or bytes(previous[1]) != parent_hash):
                self._db.execute("DELETE FROM mined_block_stats")
            self._db.execute(
                "INSERT OR REPLACE INTO mined_block_stats(height, block_hash, block_weight, mempool_txs_weight) "
                "VALUES(?, ?, ?, ?)",
                (height, block_hash, block_weight, mempool_txs_weight),
            )
            self._db.execute(
                "DELETE FROM mined_block_stats WHERE height NOT IN "
                "(SELECT height FROM mined_block_stats ORDER BY height DESC LIMIT ?)",
                (HEALTH_WINDOW_BLOCKS,),
            )

    def recent_blocks(self) -> tuple[MinedBlockStats, ...]:
        rows = self._db.execute(
            "SELECT height, block_hash, block_weight, mempool_txs_weight "
            "FROM mined_block_stats ORDER BY height"
        ).fetchall()
        return tuple(
            MinedBlockStats(int(row[0]), bytes(row[1]), int(row[2]), int(row[3]))
            for row in rows
        )

    def health(self) -> tuple[bool, str | None]:
        blocks = self.recent_blocks()
        if len(blocks) < HEALTH_WINDOW_BLOCKS:
            return False, "Not enough recent block data for fee rate estimation"
        if any(right.height != left.height + 1 for left, right in zip(blocks, blocks[1:])):
            return False, "Not enough recent block data for fee rate estimation"
        total_weight = sum(block.block_weight for block in blocks)
        if total_weight < MIN_REPRESENTATIVE_WEIGHT:
            return True, None
        represented = sum(block.mempool_txs_weight for block in blocks)
        if represented / total_weight < MIN_MEMPOOL_REPRESENTATION:
            return False, "Mempool is unreliable for fee rate estimation"
        return True, None

    def estimate(self, *, conservative: bool = False) -> tuple[float | None, str | None]:
        """Return a sat/vB percentile, or an explanatory error when data is weak."""
        healthy, error = self.health()
        if not healthy:
            return None, error
        from bitcoin_core.node.mining import _selected_transactions

        selected, _template, _fees = _selected_transactions(self.mempool, segwit_active=True)
        ranked = sorted(
            (
                (entry.fee / max(1, entry.vsize), max(entry.weight, entry.vsize * 4))
                for entry in selected
            ),
            key=lambda item: item[0],
            reverse=True,
        )
        threshold = BLOCK_MAX_WEIGHT * (1 if conservative else 3) // (2 if conservative else 4)
        accumulated = 0
        rate: float | None = None
        for fee_rate, weight in ranked:
            accumulated += weight
            if accumulated >= threshold:
                rate = fee_rate
                break
        floor = self.mempool.min_relay_fee_per_kvb / 1_000
        if rate is None:
            rate = floor
        return max(rate, floor), None
