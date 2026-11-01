"""SegWit witness-program recognition and version-0 execution."""

from __future__ import annotations

from bitcoin_core.crypto.hashes import hash160, sha256
from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.script import opcodes as op
from bitcoin_core.script.interpreter import (
    ScriptError,
    ScriptFlags,
    ScriptTransactionContext,
    cast_to_bool,
    eval_script,
    is_push_only,
)
from bitcoin_core.script.sighash import TransactionSignatureChecker


def get_witness_program(script_pubkey: bytes) -> tuple[int, bytes] | None:
    """Parse a standard witness-program output script."""
    if len(script_pubkey) < 4 or len(script_pubkey) > 42:
        return None
    version_opcode = script_pubkey[0]
    if version_opcode == op.OP_0:
        version = 0
    elif op.OP_1 <= version_opcode <= op.OP_16:
        version = version_opcode - op.OP_1 + 1
    else:
        return None
    size = script_pubkey[1]
    if not 2 <= size <= 40 or size + 2 != len(script_pubkey):
        return None
    return version, script_pubkey[2:]


def _encode_push(data: bytes) -> bytes:
    size = len(data)
    if size <= 75:
        return bytes((size,)) + data
    if size <= 0xFF:
        return bytes((op.OP_PUSHDATA1, size)) + data
    if size <= 0xFFFF:
        return bytes((op.OP_PUSHDATA2,)) + size.to_bytes(2, "little") + data
    return bytes((op.OP_PUSHDATA4,)) + size.to_bytes(4, "little") + data


def verify_witness_v0(
    tx: Transaction,
    input_index: int,
    amount: int,
    program: bytes,
    witness: tuple[bytes, ...] | list[bytes],
    *,
    flags: ScriptFlags = ScriptFlags.NONE,
) -> bool:
    """Verify a version-0 P2WPKH or P2WSH witness stack."""
    if not 0 <= input_index < len(tx.inputs) or not witness:
        return False
    if any(len(item) > 520 for item in witness[:-1]):
        return False
    if len(program) == 20:
        if len(witness) != 2 or any(len(item) > 520 for item in witness):
            return False
        script_code = b"\x76\xa9\x14" + program + b"\x88\xac"
        stack = list(witness)
    elif len(program) == 32:
        witness_script = witness[-1]
        if len(witness[:-1]) > 1_000 or len(witness_script) > 10_000 or sha256(witness_script) != program:
            return False
        script_code = witness_script
        stack = list(witness[:-1])
    else:
        return False
    checker = TransactionSignatureChecker(
        tx,
        input_index,
        amount=amount,
        witness_v0=True,
        strict_hash_type=bool(flags & ScriptFlags.STRICTENC),
        low_s=bool(flags & ScriptFlags.LOW_S),
    )
    try:
        result = eval_script(
            script_code,
            stack,
            checker=checker,
            flags=flags | ScriptFlags.CLEAN_STACK,
            tx_context=ScriptTransactionContext(tx, input_index),
        )
    except (ScriptError, ValueError):
        return False
    return len(result) == 1 and cast_to_bool(result[-1])


def verify_segwit_input(
    tx: Transaction,
    input_index: int,
    amount: int,
    script_pubkey: bytes,
    script_sig: bytes,
    witness: tuple[bytes, ...] | list[bytes],
    *,
    flags: ScriptFlags = ScriptFlags.NONE,
) -> bool:
    """Verify native or P2SH-wrapped SegWit input spending."""
    program = get_witness_program(script_pubkey)
    if program is None and len(script_pubkey) == 23 and script_pubkey[:2] == b"\xa9\x14" and script_pubkey[-1] == op.OP_EQUAL:
        if not is_push_only(script_sig):
            return False
        try:
            pushes = eval_script(script_sig)
        except ScriptError:
            return False
        if len(pushes) != 1:
            return False
        redeem_script = pushes[0]
        if _encode_push(redeem_script) != script_sig or hash160(redeem_script) != script_pubkey[2:22]:
            return False
        program = get_witness_program(redeem_script)
        if program is None:
            return False
    else:
        if script_sig:
            return False
    if program is None:
        return False
    version, witness_program = program
    if version != 0:
        return not bool(flags & ScriptFlags.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
    return verify_witness_v0(tx, input_index, amount, witness_program, witness, flags=flags)
