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

__all__ = [
    "ConsensusParams",
    "BlockConnectionError",
    "BlockUndo",
    "Coin",
    "CoinsView",
    "MAINNET",
    "REGTEST",
    "TESTNET",
    "block_proof",
    "block_subsidy",
    "calculate_next_work_required",
    "check_proof_of_work",
    "connect_block",
    "decode_compact_target",
    "disconnect_block",
    "encode_compact_target",
]
