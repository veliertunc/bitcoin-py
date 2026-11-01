"""Network-specific consensus constants used by validation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConsensusParams:
    """Proof-of-work and subsidy parameters for a Bitcoin network."""

    pow_limit: int
    target_spacing: int = 600
    target_timespan: int = 14 * 24 * 60 * 60
    subsidy_halving_interval: int = 210_000
    allow_min_difficulty: bool = False
    no_retargeting: bool = False
    enforce_bip94: bool = False

    def __post_init__(self) -> None:
        if not 0 < self.pow_limit < 1 << 256:
            raise ValueError("proof-of-work limit must be a positive uint256")
        if self.target_spacing <= 0 or self.target_timespan <= 0:
            raise ValueError("proof-of-work timing values must be positive")
        if self.subsidy_halving_interval <= 0:
            raise ValueError("subsidy halving interval must be positive")

    @property
    def difficulty_adjustment_interval(self) -> int:
        return self.target_timespan // self.target_spacing


_MAINNET_POW_LIMIT = int("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
_REGTEST_POW_LIMIT = int("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

MAINNET = ConsensusParams(pow_limit=_MAINNET_POW_LIMIT)
TESTNET = ConsensusParams(pow_limit=_MAINNET_POW_LIMIT, allow_min_difficulty=True, enforce_bip94=True)
REGTEST = ConsensusParams(pow_limit=_REGTEST_POW_LIMIT, no_retargeting=True)
