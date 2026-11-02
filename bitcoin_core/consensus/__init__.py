"""Consensus parameters and block validation primitives."""

from .params import MAINNET, REGTEST, TESTNET, ConsensusParams
from .pow import (
    block_proof,
    calculate_next_work_required,
    check_proof_of_work,
    decode_compact_target,
    encode_compact_target,
)
from .subsidy import block_subsidy
from .chainstate import BlockConnectionError, BlockUndo, Coin, CoinsView, connect_block, disconnect_block
from .blockfilter import (
    basic_filter_elements,
    compact_filter_hash,
    compact_filter_header,
    encode_basic_filter,
    match_basic_filter,
)
from .versionbits import (
    ALWAYS_ACTIVE,
    NEVER_ACTIVE,
    Deployment,
    DeploymentInfo,
    DeploymentStatistics,
    ThresholdState,
    VersionBits,
    compute_block_version,
)

__all__ = [
    "ConsensusParams",
    "Deployment",
    "DeploymentInfo",
    "DeploymentStatistics",
    "ThresholdState",
    "VersionBits",
    "ALWAYS_ACTIVE",
    "NEVER_ACTIVE",
    "BlockConnectionError",
    "BlockUndo",
    "Coin",
    "CoinsView",
    "MAINNET",
    "REGTEST",
    "TESTNET",
    "block_proof",
    "basic_filter_elements",
    "block_subsidy",
    "calculate_next_work_required",
    "check_proof_of_work",
    "connect_block",
    "decode_compact_target",
    "disconnect_block",
    "compact_filter_hash",
    "compact_filter_header",
    "compute_block_version",
    "encode_basic_filter",
    "match_basic_filter",
    "encode_compact_target",
]
