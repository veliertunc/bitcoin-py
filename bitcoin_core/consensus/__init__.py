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

__all__ = [
    "ConsensusParams",
    "MAINNET",
    "REGTEST",
    "TESTNET",
    "block_proof",
    "block_subsidy",
    "calculate_next_work_required",
    "check_proof_of_work",
    "decode_compact_target",
    "encode_compact_target",
]
