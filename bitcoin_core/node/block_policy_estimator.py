"""Historical transaction-confirmation fee estimator based on Bitcoin Core."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from bitcoin_core.node.mempool import MempoolEntry

MIN_BUCKET_FEERATE = 100.0  # sat/kvB
MAX_BUCKET_FEERATE = 10_000_000.0
FEE_SPACING = 1.05
INF_FEERATE = 1e99
SUCCESS_PCT = 0.85
HALF_SUCCESS_PCT = 0.60
DOUBLE_SUCCESS_PCT = 0.95
SUFFICIENT_TXS = 0.1
SUFFICIENT_TXS_SHORT = 0.5


@dataclass(frozen=True, slots=True)
class EstimatorBucket:
    start: float = -1.0
    end: float = -1.0
    within_target: float = 0.0
    total_confirmed: float = 0.0
    in_mempool: float = 0.0
    left_mempool: float = 0.0


@dataclass(frozen=True, slots=True)
class RawFeeStats:
    pass_bucket: EstimatorBucket
    fail_bucket: EstimatorBucket
    decay: float
    scale: int


@dataclass(slots=True)
class _Horizon:
    periods: int
    scale: int
    decay: float
    tx_average: list[float]
    fee_average: list[float]
    confirmed: list[list[float]]
    failed: list[list[float]]
    unconfirmed: list[list[int]]
    old_unconfirmed: list[int]

    @classmethod
    def create(cls, buckets: int, periods: int, scale: int, decay: float) -> _Horizon:
        return cls(
            periods,
            scale,
            decay,
            [0.0] * buckets,
            [0.0] * buckets,
            [[0.0] * buckets for _ in range(periods)],
            [[0.0] * buckets for _ in range(periods)],
            [[0] * buckets for _ in range(periods * scale)],
            [0] * buckets,
        )

    def add(self, height: int, bucket: int) -> None:
        self.unconfirmed[height % len(self.unconfirmed)][bucket] += 1

    def advance(self, height: int) -> None:
        index = height % len(self.unconfirmed)
        for bucket, count in enumerate(self.unconfirmed[index]):
            self.old_unconfirmed[bucket] += count
            self.unconfirmed[index][bucket] = 0
        for bucket in range(len(self.tx_average)):
            self.tx_average[bucket] *= self.decay
            self.fee_average[bucket] *= self.decay
            for period in range(self.periods):
                self.confirmed[period][bucket] *= self.decay
                self.failed[period][bucket] *= self.decay

    def remove(self, entry_height: int, best_height: int, bucket: int, *, in_block: bool) -> None:
        blocks_ago = max(0, best_height - entry_height)
        if blocks_ago >= len(self.unconfirmed):
            if self.old_unconfirmed[bucket] > 0:
                self.old_unconfirmed[bucket] -= 1
        else:
            index = entry_height % len(self.unconfirmed)
            if self.unconfirmed[index][bucket] > 0:
                self.unconfirmed[index][bucket] -= 1
        if not in_block and blocks_ago >= self.scale:
            for period in range(min(blocks_ago // self.scale, self.periods)):
                self.failed[period][bucket] += 1

    def record(self, blocks_to_confirm: int, bucket: int, feerate: float) -> None:
        if blocks_to_confirm < 1:
            return
        first_period = (blocks_to_confirm + self.scale - 1) // self.scale
        for period in range(first_period - 1, self.periods):
            self.confirmed[period][bucket] += 1
        self.tx_average[bucket] += 1
        self.fee_average[bucket] += feerate

    def estimate(
        self,
        target: int,
        sufficient: float,
        success: float,
        height: int,
        bucket_boundaries: list[float],
    ) -> tuple[float, RawFeeStats]:
        """Return the median feerate and Core-style pass/fail bucket statistics."""
        pass_bucket = EstimatorBucket()
        fail_bucket = EstimatorBucket()
        result = RawFeeStats(pass_bucket, fail_bucket, self.decay, self.scale)
        if not 1 <= target <= self.periods * self.scale:
            return -1.0, result
        target_period = (target + self.scale - 1) // self.scale
        bins = len(self.unconfirmed)
        n_conf = total = failed = 0.0
        extra = 0
        partial = 0.0
        near = far = best_near = best_far = len(self.tx_average) - 1
        new_range = True
        passing = True
        found = False
        for bucket in range(len(self.tx_average) - 1, -1, -1):
            if new_range:
                near = bucket
                new_range = False
            far = bucket
            n_conf += self.confirmed[target_period - 1][bucket]
            partial += self.tx_average[bucket]
            total += self.tx_average[bucket]
            failed += self.failed[target_period - 1][bucket]
            for age in range(target, bins):
                extra += self.unconfirmed[(height - age) % bins][bucket]
            extra += self.old_unconfirmed[bucket]
            if partial < sufficient / (1 - self.decay):
                continue
            partial = 0.0
            success_ratio = n_conf / (total + failed + extra) if total + failed + extra else 0.0
            if success_ratio < success:
                if passing:
                    low, high = sorted((near, far))
                    fail_bucket = EstimatorBucket(
                        0.0 if low == 0 else bucket_boundaries[low - 1],
                        bucket_boundaries[high],
                        n_conf,
                        total,
                        extra,
                        failed,
                    )
                passing = False
                continue
            found = True
            fail_bucket = EstimatorBucket()
            passing = True
            pass_bucket = EstimatorBucket(
                -1.0,
                -1.0,
                n_conf,
                total,
                extra,
                failed,
            )
            n_conf = total = failed = 0.0
            extra = 0
            best_near, best_far = near, far
            new_range = True

        if passing and not new_range:
            low, high = sorted((near, far))
            fail_bucket = EstimatorBucket(
                0.0 if low == 0 else bucket_boundaries[low - 1],
                bucket_boundaries[high],
                n_conf,
                total,
                extra,
                failed,
            )

        if not found:
            return -1.0, RawFeeStats(pass_bucket, fail_bucket, self.decay, self.scale)
        low, high = sorted((best_near, best_far))
        tx_count = sum(self.tx_average[low : high + 1])
        if tx_count <= 0:
            return -1.0, RawFeeStats(pass_bucket, fail_bucket, self.decay, self.scale)
        midpoint = tx_count / 2
        for bucket in range(low, high + 1):
            if self.tx_average[bucket] < midpoint:
                midpoint -= self.tx_average[bucket]
                continue
            if self.tx_average[bucket] > 0:
                median = self.fee_average[bucket] / self.tx_average[bucket]
                pass_bucket = EstimatorBucket(
                    0.0 if low == 0 else bucket_boundaries[low - 1],
                    bucket_boundaries[high],
                    pass_bucket.within_target,
                    pass_bucket.total_confirmed,
                    pass_bucket.in_mempool,
                    pass_bucket.left_mempool,
                )
                return median, RawFeeStats(pass_bucket, fail_bucket, self.decay, self.scale)
        return -1.0, RawFeeStats(pass_bucket, fail_bucket, self.decay, self.scale)


@dataclass(slots=True)
class BlockPolicyEstimator:
    """Track fee buckets, confirmation delays, and decaying estimates by horizon."""

    path: str | Path | None = None
    buckets: list[float] = field(init=False)
    horizons: tuple[_Horizon, _Horizon, _Horizon] = field(init=False)
    tracked: dict[bytes, tuple[int, int, float]] = field(default_factory=dict)
    best_height: int = 0
    first_recorded_height: int = 0
    _db: sqlite3.Connection | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.buckets = []
        rate = MIN_BUCKET_FEERATE
        while rate <= MAX_BUCKET_FEERATE:
            self.buckets.append(rate)
            rate *= FEE_SPACING
        self.buckets.append(INF_FEERATE)
        count = len(self.buckets)
        self.horizons = (
            _Horizon.create(count, 12, 1, 0.962),
            _Horizon.create(count, 24, 2, 0.9952),
            _Horizon.create(count, 42, 24, 0.99931),
        )
        if self.path is not None:
            self._db = sqlite3.connect(str(self.path))
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS block_policy_state "
                "(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, payload TEXT NOT NULL)"
            )
            self._load()

    def _load(self) -> None:
        if self._db is None:
            return
        row = self._db.execute(
            "SELECT version, payload FROM block_policy_state WHERE id=1"
        ).fetchone()
        if row is None or row[0] != 1:
            return
        try:
            payload = json.loads(row[1])
            if len(payload["horizons"]) != len(self.horizons):
                return
            loaded_horizons = []
            for current, saved in zip(self.horizons, payload["horizons"]):
                values = {}
                for item in fields(_Horizon):
                    name = item.name
                    saved_value = saved[name]
                    current_value = getattr(current, name)
                    if isinstance(current_value, list):
                        if len(saved_value) != len(current_value):
                            raise ValueError("fee estimate horizon shape mismatch")
                        if current_value and isinstance(current_value[0], list):
                            if any(len(row) != len(current_value[0]) for row in saved_value):
                                raise ValueError("fee estimate bucket shape mismatch")
                        values[name] = saved_value
                    else:
                        values[name] = saved_value
                loaded_horizons.append(_Horizon(**values))
            self.horizons = tuple(loaded_horizons)
            # Outstanding transactions are deliberately re-learned after a
            # restart; only confirmed historical averages are persisted.
            self.tracked.clear()
            self.best_height = max(0, int(payload["best_height"]))
            self.first_recorded_height = max(0, int(payload["first_recorded_height"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.tracked.clear()
            self.best_height = 0
            self.first_recorded_height = 0
            self.horizons = (
                _Horizon.create(len(self.buckets), 12, 1, 0.962),
                _Horizon.create(len(self.buckets), 24, 2, 0.9952),
                _Horizon.create(len(self.buckets), 42, 24, 0.99931),
            )

    def flush(self) -> None:
        """Persist estimator counters and tracked transactions atomically."""
        if self._db is None:
            return
        payload = json.dumps(
            {
                "best_height": self.best_height,
                "first_recorded_height": self.first_recorded_height,
                "horizons": [asdict(horizon) for horizon in self.horizons],
            },
            separators=(",", ":"),
        )
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO block_policy_state(id, version, payload) VALUES(1, 1, ?)",
                (payload,),
            )

    def close(self) -> None:
        if self._db is not None:
            self.flush_unconfirmed()
            self.flush()
            self._db.close()
            self._db = None

    def flush_unconfirmed(self) -> None:
        """Record still-pending observations as non-confirmations at shutdown."""
        for txid in tuple(self.tracked):
            self.remove_transaction(txid)

    def _bucket(self, feerate: float) -> int:
        low, high = 0, len(self.buckets)
        while low < high:
            mid = (low + high) // 2
            if self.buckets[mid] < feerate:
                low = mid + 1
            else:
                high = mid
        return min(low, len(self.buckets) - 1)

    def process_transaction(self, entry: MempoolEntry, chain_height: int) -> None:
        """Track eligible parentless transactions accepted at the current tip."""
        if entry.parents or entry.txid in self.tracked or entry.height != chain_height + 1:
            return
        feerate = entry.fee * 1_000 / max(1, entry.vsize)
        bucket = self._bucket(feerate)
        entry_height = chain_height
        self.tracked[entry.txid] = entry_height, bucket, feerate
        for horizon in self.horizons:
            horizon.add(entry_height, bucket)

    def remove_transaction(self, txid: bytes) -> bool:
        """Forget an unconfirmed transaction and record it as a non-confirmation."""
        data = self.tracked.pop(txid, None)
        if data is None:
            return False
        entry_height, bucket, _feerate = data
        for horizon in self.horizons:
            horizon.remove(entry_height, self.best_height, bucket, in_block=False)
        return True

    def process_block(self, height: int, confirmed_txids: tuple[bytes, ...] | list[bytes]) -> None:
        """Advance moving averages and record tracked confirmations in one block."""
        if height <= self.best_height:
            return
        self.best_height = height
        for horizon in self.horizons:
            horizon.advance(height)
        counted = 0
        for txid in confirmed_txids:
            data = self.tracked.pop(txid, None)
            if data is None:
                continue
            entry_height, bucket, feerate = data
            blocks_to_confirm = height - entry_height
            for horizon in self.horizons:
                horizon.remove(entry_height, height, bucket, in_block=True)
                horizon.record(blocks_to_confirm, bucket, feerate)
            counted += 1
        if counted and self.first_recorded_height == 0:
            self.first_recorded_height = height

    def _span(self) -> int:
        return max(0, self.best_height - self.first_recorded_height) if self.first_recorded_height else 0

    def maximum_target(self) -> int:
        return min(1_008, self._span() // 2)

    def _combined(self, target: int, success: float, *, shorter: bool) -> float:
        if not 1 <= target <= 1_008:
            return -1.0
        short, medium, long = self.horizons
        if target <= 12:
            primary, sufficient = short, SUFFICIENT_TXS_SHORT
        elif target <= 48:
            primary, sufficient = medium, SUFFICIENT_TXS
        else:
            primary, sufficient = long, SUFFICIENT_TXS
        estimate, _stats = primary.estimate(
            target, sufficient, success, self.best_height, self.buckets
        )
        if shorter:
            for horizon, limit, enough in (
                (medium, 48, SUFFICIENT_TXS),
                (short, 12, SUFFICIENT_TXS_SHORT),
            ):
                if target > limit:
                    candidate, _stats = horizon.estimate(
                        limit, enough, success, self.best_height, self.buckets
                    )
                    if candidate > 0 and (estimate < 0 or candidate < estimate):
                        estimate = candidate
        return estimate

    def estimate_smart_fee(self, target: int, *, conservative: bool = False) -> tuple[float | None, int]:
        """Return a sat/kvB estimate and adjusted target, or no estimate."""
        if not 1 <= target <= 1_008:
            return None, target
        selected = max(2, target)
        selected = min(selected, self.maximum_target())
        if selected <= 1:
            return None, selected
        half = self._combined(selected // 2, HALF_SUCCESS_PCT, shorter=True)
        full = self._combined(selected, SUCCESS_PCT, shorter=True)
        doubled = self._combined(2 * selected, DOUBLE_SUCCESS_PCT, shorter=not conservative)
        estimate = max(half, full, doubled)
        if conservative or estimate < 0:
            medium, _stats = self.horizons[1].estimate(
                2 * selected, SUFFICIENT_TXS, DOUBLE_SUCCESS_PCT, self.best_height, self.buckets
            )
            long, _stats = self.horizons[2].estimate(
                2 * selected, SUFFICIENT_TXS, DOUBLE_SUCCESS_PCT, self.best_height, self.buckets
            )
            estimate = max(estimate, medium, long)
        return (estimate if estimate >= 0 else None), selected

    def estimate_raw_fee(self, target: int, threshold: float, horizon_name: str) -> tuple[float, RawFeeStats]:
        """Return raw bucket statistics for one of Core's three time horizons."""
        horizons = {"short": self.horizons[0], "medium": self.horizons[1], "long": self.horizons[2]}
        horizon = horizons[horizon_name]
        sufficient = SUFFICIENT_TXS_SHORT if horizon_name == "short" else SUFFICIENT_TXS
        if not 0 <= threshold <= 1:
            return -1.0, RawFeeStats(
                EstimatorBucket(), EstimatorBucket(), horizon.decay, horizon.scale
            )
        return horizon.estimate(target, sufficient, threshold, self.best_height, self.buckets)
