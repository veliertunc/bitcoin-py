"""Context-free checks for block structure and proof of work."""

from __future__ import annotations

from dataclasses import dataclass

from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.consensus.pow import check_proof_of_work
from bitcoin_core.primitives.block import Block, merkle_root
from bitcoin_core.serialization.compact_size import write_compact_size

MAX_BLOCK_WEIGHT = 4_000_000


@dataclass(frozen=True, slots=True)
class BlockCheckResult:
    valid: bool
    reason: str = ""


def check_block(block: Block, params: ConsensusParams, *, check_pow: bool = True) -> BlockCheckResult:
    """Check context-free block structure, Merkle commitment, and proof of work."""
    if not block.transactions:
        return BlockCheckResult(False, "block has no transactions")
    if not block.transactions[0].inputs or not block.transactions[0].inputs[0].previous_output.is_null:
        return BlockCheckResult(False, "first transaction is not coinbase")
    if any(txin.previous_output.is_null for tx in block.transactions[1:] for txin in tx.inputs):
        return BlockCheckResult(False, "non-coinbase transaction contains a null prevout")
    if any(not tx.inputs for tx in block.transactions):
        return BlockCheckResult(False, "transaction has no inputs")
    if any(not tx.outputs for tx in block.transactions):
        return BlockCheckResult(False, "transaction has no outputs")
    txids = [tx.txid for tx in block.transactions]
    if len(set(txids)) != len(txids):
        return BlockCheckResult(False, "duplicate transaction")
    for tx in block.transactions:
        prevouts = [(txin.previous_output.txid, txin.previous_output.index) for txin in tx.inputs]
        if len(set(prevouts)) != len(prevouts):
            return BlockCheckResult(False, "transaction contains duplicate inputs")
    total_size = len(block.serialize())
    stripped_size = len(block.header.serialize()) + len(write_compact_size(len(block.transactions)))
    stripped_size += sum(len(tx.serialize(include_witness=False)) for tx in block.transactions)
    if stripped_size * 3 + total_size > MAX_BLOCK_WEIGHT:
        return BlockCheckResult(False, "block weight exceeds maximum")
    try:
        for tx in block.transactions:
            tx.output_value()
    except ValueError as exc:
        return BlockCheckResult(False, str(exc))
    if len(block.transactions[0].inputs[0].script_sig) < 2:
        return BlockCheckResult(False, "coinbase scriptSig is shorter than 2 bytes")
    if len(block.transactions[0].inputs[0].script_sig) > 100:
        return BlockCheckResult(False, "coinbase scriptSig is longer than 100 bytes")
    root, mutated = merkle_root([tx.txid for tx in block.transactions])
    if mutated:
        return BlockCheckResult(False, "mutated Merkle tree")
    if root != block.header.merkle_root:
        return BlockCheckResult(False, "Merkle root mismatch")
    if check_pow and not check_proof_of_work(block.header, params):
        return BlockCheckResult(False, "proof of work does not match target")
    return BlockCheckResult(True)
