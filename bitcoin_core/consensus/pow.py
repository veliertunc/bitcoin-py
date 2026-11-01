"""Compact target arithmetic and proof-of-work validation."""

from __future__ import annotations

from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.primitives.block import BlockHeader

UINT256_LIMIT = 1 << 256


def decode_compact_target(compact: int) -> tuple[int, bool, bool]:
    """Decode uint32 compact target into (target, negative, overflow)."""
    if not 0 <= compact <= 0xFFFFFFFF:
        raise ValueError("compact target must fit in uint32")
    size = compact >> 24
    word = compact & 0x007FFFFF
    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))
    negative = word != 0 and bool(compact & 0x00800000)
    overflow = word != 0 and (
        size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32)
    )
    return target, negative, overflow


def encode_compact_target(target: int, *, negative: bool = False) -> int:
    """Encode a positive target as Bitcoin's compact uint32 representation."""
    if not 0 <= target < UINT256_LIMIT:
        raise ValueError("target must fit in uint256")
    if target == 0:
        return 0
    size = (target.bit_length() + 7) // 8
    compact = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    compact &= 0x007FFFFF
    compact |= size << 24
    if negative and (compact & 0x007FFFFF):
        compact |= 0x00800000
    return compact


def check_proof_of_work(header: BlockHeader, params: ConsensusParams) -> bool:
    """Return whether a block header's hash satisfies its compact target."""
    target, negative, overflow = decode_compact_target(header.bits)
    if negative or target == 0 or overflow or target > params.pow_limit:
        return False
    return int.from_bytes(header.block_hash, "little") <= target


def block_proof(compact: int) -> int:
    """Return the expected chainwork contribution for a compact target."""
    target, negative, overflow = decode_compact_target(compact)
    if negative or target == 0 or overflow:
        return 0
    return UINT256_LIMIT // (target + 1)


def calculate_next_work_required(
    previous_bits: int,
    actual_timespan: int,
    params: ConsensusParams,
    *,
    period_first_bits: int | None = None,
) -> int:
    """Calculate a retargeted nBits value from one adjustment period."""
    if params.no_retargeting:
        return previous_bits
    target_timespan = params.target_timespan
    actual_timespan = max(target_timespan // 4, min(actual_timespan, target_timespan * 4))
    base_bits = period_first_bits if period_first_bits is not None else previous_bits
    target, negative, overflow = decode_compact_target(base_bits)
    if negative or target == 0 or overflow:
        raise ValueError("cannot retarget an invalid compact target")
    new_target = min(target * actual_timespan // target_timespan, params.pow_limit)
    return encode_compact_target(new_target)
