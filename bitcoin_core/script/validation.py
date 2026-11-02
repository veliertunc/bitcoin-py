"""Transaction-input script verification across legacy and witness programs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from bitcoin_core.crypto.hashes import hash160
from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.script import opcodes as op
from bitcoin_core.script.interpreter import ScriptError, ScriptFlags, ScriptTransactionContext, eval_script, is_push_only, verify_script
from bitcoin_core.script.sighash import TransactionSignatureChecker
from bitcoin_core.script.taproot import SpentOutput, verify_taproot_keypath, verify_taproot_scriptpath
from bitcoin_core.script.witness import get_witness_program, verify_segwit_input

ACTIVE_SCRIPT_FLAGS = (
    ScriptFlags.P2SH
    | ScriptFlags.STRICTENC
    | ScriptFlags.MINIMAL_DATA
    | ScriptFlags.NULL_DUMMY
    | ScriptFlags.CLEAN_STACK
    | ScriptFlags.DISCOURAGE_UPGRADABLE_NOPS
    | ScriptFlags.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | ScriptFlags.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
    | ScriptFlags.DISCOURAGE_OP_SUCCESS
    | ScriptFlags.DISCOURAGE_UPGRADABLE_PUBKEYTYPE
    | ScriptFlags.NULLFAIL
    | ScriptFlags.LOW_S
    | ScriptFlags.WITNESS_PUBKEYTYPE
    | ScriptFlags.CONST_SCRIPTCODE
    | ScriptFlags.CHECKLOCKTIMEVERIFY
    | ScriptFlags.CHECKSEQUENCEVERIFY
    | ScriptFlags.TAPROOT
    | ScriptFlags.MINIMAL_IF
    | ScriptFlags.DERSIG
    | ScriptFlags.WITNESS
)


def consensus_script_flags(
    params: ConsensusParams,
    height: int,
    block_hash: bytes | None = None,
) -> ScriptFlags:
    """Return the source revision's consensus script rules for a candidate block."""
    # Core keeps P2SH, witness, and Taproot enabled for historical validation,
    # except at the two P2SH and one Taproot exception blocks.
    flags = ScriptFlags.P2SH | ScriptFlags.WITNESS | ScriptFlags.TAPROOT
    if block_hash is not None:
        for exception_hash, exception_mask in params.script_flag_exceptions:
            if block_hash == exception_hash:
                flags &= ScriptFlags(exception_mask)
                break
    if params.bip66_height is not None and height >= params.bip66_height:
        flags |= ScriptFlags.DERSIG
    if params.bip65_height is not None and height >= params.bip65_height:
        flags |= ScriptFlags.CHECKLOCKTIMEVERIFY
    if params.csv_height is not None and height >= params.csv_height:
        flags |= ScriptFlags.CHECKSEQUENCEVERIFY
    if params.segwit_height is not None and height >= params.segwit_height:
        flags |= ScriptFlags.NULL_DUMMY
    return flags


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
    flags: ScriptFlags = ACTIVE_SCRIPT_FLAGS,
) -> bool:
    """Verify one input using its spent output and all transaction prevouts."""
    if not 0 <= input_index < len(tx.inputs) or len(all_prevouts) != len(tx.inputs):
        return False
    txin = tx.inputs[input_index]
    witness = txin.witness
    if witness and not flags & ScriptFlags.WITNESS:
        return False
    program = get_witness_program(prevout.script_pubkey) if flags & ScriptFlags.WITNESS else None
    nested_program = None
    if program is None and flags & ScriptFlags.P2SH and flags & ScriptFlags.WITNESS:
        redeem = _p2sh_redeem_script(txin.script_sig, prevout.script_pubkey)
        if redeem is not None:
            nested_program = get_witness_program(redeem)
    active_program = program if program is not None else nested_program
    if (
        active_program is not None
        and active_program[0] == 1
        and len(active_program[1]) == 32
        and flags & ScriptFlags.TAPROOT
    ):
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
    if active_program is not None and flags & ScriptFlags.WITNESS:
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
        strict_der=bool(flags & ScriptFlags.DERSIG),
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


@dataclass(frozen=True, slots=True)
class ConsensusScriptVerifier:
    """Input verifier that selects consensus flags at the candidate height."""

    params: ConsensusParams

    def __call__(
        self,
        tx: Transaction,
        input_index: int,
        prevout: SpentCoin,
        all_prevouts: tuple[SpentCoin, ...],
    ) -> bool:
        """Verify with all modern rules when no candidate height was supplied."""
        return verify_transaction_input(tx, input_index, prevout, all_prevouts, flags=ACTIVE_SCRIPT_FLAGS)

    def verify_at_height(
        self,
        tx: Transaction,
        input_index: int,
        prevout: SpentCoin,
        all_prevouts: tuple[SpentCoin, ...],
        height: int,
        block_hash: bytes | None = None,
    ) -> bool:
        """Verify against the buried deployment state for this block height."""
        return verify_transaction_input(
            tx,
            input_index,
            prevout,
            all_prevouts,
            flags=consensus_script_flags(self.params, height, block_hash),
        )
