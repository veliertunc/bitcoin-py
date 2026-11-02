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
    bip34_height: int | None = None
    signet_challenge: bytes = b""
    p2sh_height: int | None = None
    bip66_height: int | None = None
    bip65_height: int | None = None
    csv_height: int | None = None
    segwit_height: int | None = None
    script_flag_exceptions: tuple[tuple[bytes, int], ...] = ()
    bip30_exception_hashes: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        if not 0 < self.pow_limit < 1 << 256:
            raise ValueError("proof-of-work limit must be a positive uint256")
        if self.target_spacing <= 0 or self.target_timespan <= 0:
            raise ValueError("proof-of-work timing values must be positive")
        if self.subsidy_halving_interval <= 0:
            raise ValueError("subsidy halving interval must be positive")
        if self.bip34_height is not None and self.bip34_height < 0:
            raise ValueError("BIP34 activation height cannot be negative")
        if len(self.signet_challenge) > 10_000:
            raise ValueError("signet challenge exceeds the maximum script size")
        for height in (
            self.p2sh_height, self.bip66_height, self.bip65_height,
            self.csv_height, self.segwit_height,
        ):
            if height is not None and height < 0:
                raise ValueError("soft-fork activation height cannot be negative")
        if any(len(block_hash) != 32 for block_hash, _flags in self.script_flag_exceptions):
            raise ValueError("script flag exception hashes must be 32 bytes")
        if any(len(block_hash) != 32 for block_hash in self.bip30_exception_hashes):
            raise ValueError("BIP30 exception hashes must be 32 bytes")

    @property
    def difficulty_adjustment_interval(self) -> int:
        return self.target_timespan // self.target_spacing


_MAINNET_POW_LIMIT = int("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
_REGTEST_POW_LIMIT = int("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

MAINNET = ConsensusParams(
    pow_limit=_MAINNET_POW_LIMIT,
    bip34_height=227_931,
    p2sh_height=173_805,
    bip66_height=363_725,
    bip65_height=388_381,
    csv_height=419_328,
    segwit_height=481_824,
    script_flag_exceptions=(
        (bytes.fromhex("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22")[::-1], 0),
        (bytes.fromhex("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad")[::-1], 1 | 32768),
    ),
    bip30_exception_hashes=(
        bytes.fromhex("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")[::-1],
        bytes.fromhex("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")[::-1],
    ),
)
TESTNET = ConsensusParams(
    pow_limit=_MAINNET_POW_LIMIT,
    allow_min_difficulty=True,
    enforce_bip94=True,
    bip34_height=21_111,
    p2sh_height=514,
    bip66_height=330_776,
    bip65_height=581_885,
    csv_height=770_112,
    segwit_height=834_624,
    script_flag_exceptions=(
        (bytes.fromhex("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105")[::-1], 0),
    ),
)
REGTEST = ConsensusParams(
    pow_limit=_REGTEST_POW_LIMIT,
    no_retargeting=True,
    bip34_height=500,
    p2sh_height=0,
    bip66_height=0,
    bip65_height=0,
    csv_height=0,
    segwit_height=0,
)
