"""Block-header index with contextual time and difficulty validation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.consensus.pow import block_proof, check_proof_of_work, calculate_next_work_required, encode_compact_target
from bitcoin_core.primitives.block import BlockHeader

MEDIAN_TIME_SPAN = 11
MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60


class HeaderValidationError(ValueError):
    """Raised when a candidate header violates chain context rules."""


@dataclass(frozen=True, slots=True)
class BlockIndex:
    """One validated header and its link to the preceding chain entry."""

    header: BlockHeader
    height: int
    previous: BlockIndex | None
    chainwork: int

    @property
    def block_hash(self) -> bytes:
        return self.header.block_hash

    @property
    def median_time_past(self) -> int:
        timestamps = []
        current: BlockIndex | None = self
        for _ in range(MEDIAN_TIME_SPAN):
            if current is None:
                break
            timestamps.append(current.header.timestamp)
            current = current.previous
        timestamps.sort()
        return timestamps[len(timestamps) // 2]

    def ancestor(self, height: int) -> BlockIndex | None:
        if height < 0 or height > self.height:
            return None
        current: BlockIndex | None = self
        while current is not None and current.height > height:
            current = current.previous
        return current


def expected_work_bits(previous: BlockIndex, timestamp: int, params: ConsensusParams) -> int:
    """Calculate nBits for a candidate block using its previous-chain context."""
    height = previous.height + 1
    interval = params.difficulty_adjustment_interval
    pow_limit_bits = encode_compact_target(params.pow_limit)
    if height % interval != 0:
        if params.allow_min_difficulty:
            if timestamp > previous.header.timestamp + params.target_spacing * 2:
                return pow_limit_bits
            cursor = previous
            while (
                cursor.previous is not None
                and cursor.height % interval != 0
                and cursor.header.bits == pow_limit_bits
            ):
                cursor = cursor.previous
            return cursor.header.bits
        return previous.header.bits

    first_height = previous.height - (interval - 1)
    first = previous.ancestor(first_height)
    if first is None:
        raise HeaderValidationError("difficulty period start is unavailable")
    elapsed = previous.header.timestamp - first.header.timestamp
    base_bits = first.header.bits if params.enforce_bip94 else previous.header.bits
    try:
        return calculate_next_work_required(
            base_bits,
            elapsed,
            params,
            period_first_bits=first.header.bits if params.enforce_bip94 else None,
        )
    except ValueError as exc:
        raise HeaderValidationError("invalid target in previous difficulty period") from exc


@dataclass(slots=True)
class HeaderChain:
    """Validated header index that selects its active tip by cumulative work."""

    params: ConsensusParams
    indexes: dict[bytes, BlockIndex] = field(default_factory=dict)
    tip: BlockIndex | None = None

    def add_genesis(self, header: BlockHeader) -> BlockIndex:
        """Add the network's genesis header to an empty index."""
        if self.indexes or self.tip is not None:
            raise HeaderValidationError("genesis is already configured")
        if header.previous_block != bytes(32):
            raise HeaderValidationError("genesis header has a non-null previous hash")
        if not check_proof_of_work(header, self.params):
            raise HeaderValidationError("genesis proof of work is invalid")
        index = BlockIndex(header, 0, None, block_proof(header.bits))
        self.indexes[index.block_hash] = index
        self.tip = index
        return index

    def add_header(self, header: BlockHeader) -> BlockIndex:
        """Validate and index a header; update the active tip if work increases."""
        previous = self.indexes.get(header.previous_block)
        if previous is None:
            raise HeaderValidationError("unknown previous block")
        if header.timestamp <= previous.median_time_past:
            raise HeaderValidationError("block timestamp is not greater than median-time-past")
        if header.timestamp > int(time.time()) + MAX_FUTURE_BLOCK_TIME:
            raise HeaderValidationError("block timestamp is too far in the future")
        height = previous.height + 1
        for activation_height, minimum_version, deployment in (
            (self.params.bip34_height, 2, "BIP34"),
            (self.params.bip66_height, 3, "BIP66"),
            (self.params.bip65_height, 4, "BIP65"),
        ):
            if activation_height is not None and height >= activation_height and header.version < minimum_version:
                raise HeaderValidationError(f"block version is below the active {deployment} minimum")
        required_bits = expected_work_bits(previous, header.timestamp, self.params)
        if header.bits != required_bits:
            raise HeaderValidationError("unexpected proof-of-work target")
        if not check_proof_of_work(header, self.params):
            raise HeaderValidationError("proof of work does not match target")
        block_hash = header.block_hash
        if block_hash in self.indexes:
            return self.indexes[block_hash]
        index = BlockIndex(
            header,
            height,
            previous,
            previous.chainwork + block_proof(header.bits),
        )
        self.indexes[block_hash] = index
        if self.tip is None or index.chainwork > self.tip.chainwork:
            self.tip = index
        return index
