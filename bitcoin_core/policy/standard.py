"""Bitcoin Core standard-transaction policy for mempool relay."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from bitcoin_core.crypto.secp256k1 import parse_public_key
from bitcoin_core.crypto.hashes import hash160
from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.script import opcodes as op
from bitcoin_core.script.interpreter import is_push_only
from bitcoin_core.script.interpreter import eval_script
from bitcoin_core.script.sigops import MAX_BLOCK_SIGOP_COST, count_sigops, input_sigop_cost, legacy_sigop_cost
from bitcoin_core.script.witness import get_witness_program

MAX_STANDARD_TX_WEIGHT = 400_000
MIN_STANDARD_TX_NONWITNESS_SIZE = 65
MAX_STANDARD_SCRIPTSIG_SIZE = 1_650
MAX_OP_RETURN_RELAY = 100_000
MAX_STANDARD_MULTISIG_KEYS = 3
DUST_RELAY_FEE_PER_KVB = 3_000
MAX_DUST_OUTPUTS_PER_TX = 1
MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOP_COST // 5
WITNESS_SCALE_FACTOR = 4


@dataclass(frozen=True, slots=True)
class StandardnessResult:
    standard: bool
    reason: str = ""


class SpentOutput(Protocol):
    script_pubkey: bytes


def _is_p2pk(script: bytes) -> bool:
    if len(script) not in (35, 67) or script[-1] != op.OP_CHECKSIG:
        return False
    key_length = script[0]
    if key_length != len(script) - 2:
        return False
    try:
        parse_public_key(script[1:-1])
    except ValueError:
        return False
    return True


def _is_bare_multisig(script: bytes) -> bool:
    if len(script) < 1 or not op.OP_1 <= script[0] <= op.OP_16 or script[-1] != op.OP_CHECKMULTISIG:
        return False
    required = script[0] - op.OP_1 + 1
    position = 1
    keys = 0
    while position < len(script) - 2:
        size = script[position]
        if size not in (33, 65) or position + size + 1 > len(script) - 2:
            return False
        try:
            parse_public_key(script[position + 1 : position + 1 + size])
        except ValueError:
            return False
        keys += 1
        position += size + 1
    if position != len(script) - 2:
        return False
    opcode_n = script[position]
    if not op.OP_1 <= opcode_n <= op.OP_16:
        return False
    declared_keys = opcode_n - op.OP_1 + 1
    return keys == declared_keys and 1 <= required <= keys <= MAX_STANDARD_MULTISIG_KEYS


def is_standard_script(script: bytes) -> tuple[bool, str]:
    """Recognize standard payment, witness, multisig, and data-carrier outputs."""
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return True, "pubkeyhash"
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1] == op.OP_EQUAL:
        return True, "scripthash"
    if get_witness_program(script) is not None:
        return True, "witness"
    if _is_p2pk(script):
        return True, "pubkey"
    if _is_bare_multisig(script):
        return True, "multisig"
    if script[:1] == bytes((op.OP_RETURN,)):
        return len(script) <= MAX_OP_RETURN_RELAY, "nulldata"
    return False, "nonstandard"


def _is_dust_output(value: int, script: bytes, *, dust_relay_fee_per_kvb: int) -> bool:
    if script[:1] == bytes((op.OP_RETURN,)):
        return False
    output_size = 8 + len(script) + (1 if len(script) < 253 else 3 if len(script) <= 0xFFFF else 5)
    witness = get_witness_program(script) is not None
    spend_size = 32 + 4 + 1 + (67 // WITNESS_SCALE_FACTOR if witness else 107) + 4
    threshold = (output_size + spend_size) * dust_relay_fee_per_kvb // 1_000
    return value < threshold


def check_standard_transaction(
    tx: Transaction,
    *,
    dust_relay_fee_per_kvb: int = DUST_RELAY_FEE_PER_KVB,
    permit_bare_multisig: bool = True,
    max_datacarrier_bytes: int = MAX_OP_RETURN_RELAY,
) -> StandardnessResult:
    """Apply local relay policy, separate from consensus block validation."""
    if not 1 <= tx.version <= 3:
        return StandardnessResult(False, "version")
    stripped_size = len(tx.serialize(include_witness=False))
    total_size = len(tx.serialize(include_witness=True))
    weight = stripped_size * 3 + total_size
    if weight > MAX_STANDARD_TX_WEIGHT:
        return StandardnessResult(False, "tx-size")
    if stripped_size < MIN_STANDARD_TX_NONWITNESS_SIZE:
        return StandardnessResult(False, "tx-size-small")
    for txin in tx.inputs:
        if len(txin.script_sig) > MAX_STANDARD_SCRIPTSIG_SIZE:
            return StandardnessResult(False, "scriptsig-size")
        if not is_push_only(txin.script_sig):
            return StandardnessResult(False, "scriptsig-not-pushonly")

    datacarrier_left = max_datacarrier_bytes
    dust_count = 0
    for txout in tx.outputs:
        standard, kind = is_standard_script(txout.script_pubkey)
        if not standard:
            return StandardnessResult(False, "scriptpubkey")
        if kind == "nulldata":
            datacarrier_left -= len(txout.script_pubkey)
            if datacarrier_left < 0:
                return StandardnessResult(False, "datacarrier")
        elif kind == "multisig" and not permit_bare_multisig:
            return StandardnessResult(False, "bare-multisig")
        if _is_dust_output(txout.value, txout.script_pubkey, dust_relay_fee_per_kvb=dust_relay_fee_per_kvb):
            dust_count += 1
    if dust_count > MAX_DUST_OUTPUTS_PER_TX:
        return StandardnessResult(False, "dust")
    return StandardnessResult(True)


def check_standard_inputs(tx: Transaction, prevouts: tuple[SpentOutput, ...]) -> StandardnessResult:
    """Check the input forms and witness resource limits used by relay policy."""
    if len(prevouts) != len(tx.inputs):
        return StandardnessResult(False, "inputs-missing")
    sigop_cost = legacy_sigop_cost(tx) + input_sigop_cost(tx, prevouts)
    if sigop_cost > MAX_STANDARD_TX_SIGOPS_COST:
        return StandardnessResult(False, "sigops")
    for txin, prevout in zip(tx.inputs, prevouts):
        script_pubkey = prevout.script_pubkey
        program = get_witness_program(script_pubkey)
        p2sh = len(script_pubkey) == 23 and script_pubkey.startswith(b"\xa9\x14") and script_pubkey[-1] == op.OP_EQUAL
        if p2sh:
            try:
                stack = eval_script(txin.script_sig)
            except ValueError:
                return StandardnessResult(False, "p2sh-redeemscript")
            if not stack:
                return StandardnessResult(False, "p2sh-redeemscript")
            redeem = stack[-1]
            if hash160(redeem) != script_pubkey[2:22]:
                return StandardnessResult(False, "p2sh-redeemscript")
            try:
                if count_sigops(redeem, accurate=True) > 15:
                    return StandardnessResult(False, "p2sh-sigops")
            except ValueError:
                return StandardnessResult(False, "p2sh-redeemscript")
            program = get_witness_program(redeem)

        if not txin.witness:
            continue
        if program is None:
            return StandardnessResult(False, "unexpected-witness")
        version, witness_program = program
        if version == 0 and len(witness_program) == 32:
            witness = txin.witness
            if not witness or len(witness[-1]) > 3_600:
                return StandardnessResult(False, "witness-script-size")
            stack_items = witness[:-1]
            if len(stack_items) > 100 or any(len(item) > 80 for item in stack_items):
                return StandardnessResult(False, "witness-stack-size")
        if version == 1 and len(witness_program) == 2 and witness_program == b"\x4e\x73":
            return StandardnessResult(False, "anchor-spend")
        if version == 1 and len(witness_program) == 32 and not p2sh:
            stack = list(txin.witness)
            if len(stack) >= 2 and stack[-1].startswith(b"\x50"):
                return StandardnessResult(False, "taproot-annex")
            if len(stack) >= 2:
                control = stack[-1]
                stack = stack[:-2]
                if not control:
                    return StandardnessResult(False, "taproot-control-block")
                if control[0] & 0xFE == 0xC0 and any(len(item) > 80 for item in stack):
                    return StandardnessResult(False, "tapscript-stack-item-size")
            elif not stack:
                return StandardnessResult(False, "taproot-witness-empty")
    return StandardnessResult(True)

