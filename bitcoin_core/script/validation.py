"""Transaction-input script verification across legacy and witness programs."""

from __future__ import annotations

from typing import Protocol

from bitcoin_core.crypto.hashes import hash160
from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.script import opcodes as op
from bitcoin_core.script.interpreter import ScriptError, ScriptFlags, ScriptTransactionContext, eval_script, is_push_only, verify_script
from bitcoin_core.script.sighash import TransactionSignatureChecker
from bitcoin_core.script.taproot import SpentOutput, verify_taproot_keypath, verify_taproot_scriptpath
from bitcoin_core.script.witness import get_witness_program, verify_segwit_input


class SpentCoin(Protocol):
    value: int
    script_pubkey: bytes


def _p2sh_redeem_script(script_sig: bytes, script_pubkey: bytes) -> bytes | None:
    if len(script_pubkey) != 23 or script_pubkey[:2] != b"\xa9\x14" or script_pubkey[-1] != op.OP_EQUAL:
        return None
    if not is_push_only(script_sig):
        return None
    try:
        pushed = eval_script(script_sig)
    except ScriptError:
        return None
    if len(pushed) != 1 or hash160(pushed[0]) != script_pubkey[2:22]:
        return None
    return pushed[0]


def verify_transaction_input(
    tx: Transaction,
    input_index: int,
    prevout: SpentCoin,
    all_prevouts: tuple[SpentCoin, ...],
    *,
    flags: ScriptFlags = ScriptFlags.P2SH,
) -> bool:
    """Verify one input using its spent output and all transaction prevouts."""
    if not 0 <= input_index < len(tx.inputs) or len(all_prevouts) != len(tx.inputs):
        return False
    txin = tx.inputs[input_index]
    witness = txin.witness
    program = get_witness_program(prevout.script_pubkey)
    nested_program = None
    if program is None:
        redeem = _p2sh_redeem_script(txin.script_sig, prevout.script_pubkey)
        if redeem is not None:
            nested_program = get_witness_program(redeem)
    active_program = program if program is not None else nested_program
    if active_program is not None and active_program[0] == 1 and len(active_program[1]) == 32:
        if program is not None and txin.script_sig:
            return False
        if nested_program is not None:
            redeem = _p2sh_redeem_script(txin.script_sig, prevout.script_pubkey)
            if redeem is None or txin.script_sig != bytes((len(redeem),)) + redeem:
                return False
        spent_outputs = tuple(SpentOutput(coin.value, coin.script_pubkey) for coin in all_prevouts)
        witness_items = list(witness)
        if len(witness_items) >= 2 and witness_items[-1].startswith(b"\x50"):
            witness_items.pop()
        is_script_path = len(witness_items) >= 2
        if is_script_path:
            return verify_taproot_scriptpath(tx, input_index, spent_outputs, witness, flags=flags)
        return verify_taproot_keypath(tx, input_index, spent_outputs, witness)
    if active_program is not None:
        return verify_segwit_input(
            tx,
            input_index,
            prevout.value,
            prevout.script_pubkey,
            txin.script_sig,
            witness,
            flags=flags,
        )
    if witness:
        return False
    checker = TransactionSignatureChecker(
        tx,
        input_index,
        strict_hash_type=bool(flags & ScriptFlags.STRICTENC),
        low_s=bool(flags & ScriptFlags.LOW_S),
    )
    try:
        return verify_script(
            txin.script_sig,
            prevout.script_pubkey,
            checker=checker,
            flags=flags,
            tx_context=ScriptTransactionContext(tx, input_index),
        )
    except (ScriptError, ValueError):
        return False
