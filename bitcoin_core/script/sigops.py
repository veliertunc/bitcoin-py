"""Consensus signature-operation counting for legacy and witness scripts."""

from __future__ import annotations

from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.script import opcodes as op
from bitcoin_core.script.interpreter import eval_script, is_push_only
from bitcoin_core.script.witness import get_witness_program

WITNESS_SCALE_FACTOR = 4
MAX_BLOCK_SIGOP_COST = 80_000
_P2SH_PREFIX = b"\xa9\x14"


def count_sigops(script: bytes, *, accurate: bool) -> int:
    """Count CHECKSIG/CHECKMULTISIG operations while skipping pushed data."""
    position = 0
    previous_opcode = op.OP_INVALIDOPCODE
    count = 0
    while position < len(script):
        opcode = script[position]
        position += 1
        size = 0
        if opcode <= 75:
            size = opcode
        elif opcode == op.OP_PUSHDATA1:
            if position + 1 > len(script):
                break
            size, position = script[position], position + 1
        elif opcode == op.OP_PUSHDATA2:
            if position + 2 > len(script):
                break
            size = int.from_bytes(script[position : position + 2], "little")
            position += 2
        elif opcode == op.OP_PUSHDATA4:
            if position + 4 > len(script):
                break
            size = int.from_bytes(script[position : position + 4], "little")
            position += 4
        if size:
            if position + size > len(script):
                break
            position += size
        elif opcode == op.OP_CHECKSIG or opcode == op.OP_CHECKSIGVERIFY:
            count += 1
        elif opcode in (op.OP_CHECKMULTISIG, op.OP_CHECKMULTISIGVERIFY):
            if accurate and op.OP_1 <= previous_opcode <= op.OP_16:
                count += previous_opcode - op.OP_1 + 1
            else:
                count += 20
        previous_opcode = opcode
    return count


def is_p2sh(script_pubkey: bytes) -> bool:
    return len(script_pubkey) == 23 and script_pubkey.startswith(_P2SH_PREFIX) and script_pubkey[-1] == op.OP_EQUAL


def _redeem_script(script_sig: bytes, script_pubkey: bytes) -> bytes | None:
    if not is_p2sh(script_pubkey) or not is_push_only(script_sig):
        return None
    try:
        stack = eval_script(script_sig)
    except ValueError:
        return None
    if not stack:
        return None
    return stack[-1]


def _witness_sigops(program: tuple[int, bytes] | None, witness: tuple[bytes, ...]) -> int:
    if program is None or program[0] != 0:
        return 0
    if len(program[1]) == 20:
        return 1
    if len(program[1]) == 32 and witness:
        try:
            return count_sigops(witness[-1], accurate=True)
        except ValueError:
            return 0
    return 0


def legacy_sigop_cost(tx: Transaction) -> int:
    """Return the transaction's legacy sigop count in block-cost units."""
    operations = sum(count_sigops(txin.script_sig, accurate=False) for txin in tx.inputs)
    operations += sum(count_sigops(txout.script_pubkey, accurate=False) for txout in tx.outputs)
    return operations * WITNESS_SCALE_FACTOR


def input_sigop_cost(
    tx: Transaction,
    prevouts: tuple[object, ...],
    *,
    p2sh_active: bool = True,
    segwit_active: bool = True,
) -> int:
    """Return P2SH and witness input sigop cost using the spent outputs."""
    cost = 0
    for txin, coin in zip(tx.inputs, prevouts):
        script_pubkey = coin.script_pubkey
        program = get_witness_program(script_pubkey) if segwit_active else None
        if p2sh_active and is_p2sh(script_pubkey):
            redeem = _redeem_script(txin.script_sig, script_pubkey)
            if redeem is not None:
                cost += count_sigops(redeem, accurate=True) * WITNESS_SCALE_FACTOR
                if segwit_active:
                    program = get_witness_program(redeem)
        if segwit_active:
            cost += _witness_sigops(program, txin.witness)
    return cost

