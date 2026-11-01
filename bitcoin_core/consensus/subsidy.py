"""Block subsidy schedule."""

from __future__ import annotations

from bitcoin_core.consensus.params import ConsensusParams

COIN = 100_000_000
INITIAL_SUBSIDY = 50 * COIN


def block_subsidy(height: int, params: ConsensusParams) -> int:
    """Return the miner subsidy in satoshis at the given block height."""
    if height < 0:
        raise ValueError("block height cannot be negative")
    halvings = height // params.subsidy_halving_interval
    if halvings >= 64:
        return 0
    return INITIAL_SUBSIDY >> halvings
