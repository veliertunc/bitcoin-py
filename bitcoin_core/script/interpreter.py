"""Bitcoin Script evaluator for legacy and witness-v0 script operations.

Transaction signature hashing is supplied by the caller through a checker
callback; this keeps script execution independent from transaction assembly.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntFlag
from typing import Callable, Iterable

from bitcoin_core.crypto.hashes import hash160, hash256, sha256
from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.script import opcodes as op

MAX_SCRIPT_SIZE = 10_000
MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_STACK_SIZE = 1_000
MAX_OPS_PER_SCRIPT = 201
MAX_PUBKEYS_PER_MULTISIG = 20

SignatureChecker = Callable[[bytes, bytes, bytes], bool]
TaprootChecker = Callable[[bytes, bytes, int], bool]


class ScriptError(ValueError):
    """Raised when script parsing or execution fails."""


@dataclass(frozen=True, slots=True)
class ScriptTransactionContext:
    """Transaction fields used by CLTV and CSV script opcodes."""

    transaction: Transaction
    input_index: int

    def __post_init__(self) -> None:
        if not 0 <= self.input_index < len(self.transaction.inputs):
            raise ValueError("script input index out of range")


class ScriptFlags(IntFlag):
    NONE = 0
    P2SH = 1
    MINIMAL_DATA = 2
    NULL_DUMMY = 4
    CLEAN_STACK = 8
    DISCOURAGE_UPGRADABLE_NOPS = 16
    DISCOURAGE_OP_SUCCESS = 32
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 64
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 128
    CHECKLOCKTIMEVERIFY = 256
    CHECKSEQUENCEVERIFY = 512
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1024
    STRICTENC = 2048
    LOW_S = 4096


def cast_to_bool(value: bytes) -> bool:
    """Interpret a stack item using Script's negative-zero false value."""
    for index, byte in enumerate(value):
        if byte != 0:
            return not (index == len(value) - 1 and byte == 0x80)
    return False


def encode_script_num(value: int) -> bytes:
    """Encode a signed-magnitude Script integer using minimal encoding."""
    if value == 0:
        return b""
    negative = value < 0
    absolute = abs(value)
    result = bytearray()
    while absolute:
        result.append(absolute & 0xFF)
        absolute >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_script_num(value: bytes, *, max_size: int = 4, minimal: bool = False) -> int:
    """Decode a signed-magnitude Script integer."""
    if len(value) > max_size:
        raise ScriptError("script number overflow")
    if minimal and value and (value[-1] & 0x7F) == 0 and (len(value) == 1 or not (value[-2] & 0x80)):
        raise ScriptError("non-minimal script number")
    if not value:
        return 0
    result = int.from_bytes(value, "little")
    if value[-1] & 0x80:
        result &= ~(0x80 << (8 * (len(value) - 1)))
        return -result
    return result


def _read_op(script: bytes, offset: int) -> tuple[int, bytes | None, int]:
    if offset >= len(script):
        raise ScriptError("unexpected end of script")
    opcode = script[offset]
    offset += 1
    if opcode <= 75:
        size = opcode
    elif opcode == op.OP_PUSHDATA1:
        if offset + 1 > len(script):
            raise ScriptError("truncated PUSHDATA1")
        size = script[offset]
        offset += 1
    elif opcode == op.OP_PUSHDATA2:
        if offset + 2 > len(script):
            raise ScriptError("truncated PUSHDATA2")
        size = int.from_bytes(script[offset : offset + 2], "little")
        offset += 2
    elif opcode == op.OP_PUSHDATA4:
        if offset + 4 > len(script):
            raise ScriptError("truncated PUSHDATA4")
        size = int.from_bytes(script[offset : offset + 4], "little")
        offset += 4
    else:
        return opcode, None, offset
    if offset + size > len(script):
        raise ScriptError("push extends beyond end of script")
    return opcode, script[offset : offset + size], offset + size


def is_push_only(script: bytes) -> bool:
    """Return whether a script contains only pushes and small integer opcodes."""
    try:
        offset = 0
        while offset < len(script):
            opcode, _, offset = _read_op(script, offset)
            if opcode > op.OP_16:
                return False
        return True
    except ScriptError:
        return False


def _require(stack: list[bytes], count: int) -> None:
    if len(stack) < count:
        raise ScriptError("stack underflow")


def _pop_num(stack: list[bytes], flags: ScriptFlags, *, max_size: int = 4) -> int:
    _require(stack, 1)
    return decode_script_num(stack.pop(), max_size=max_size, minimal=bool(flags & ScriptFlags.MINIMAL_DATA))


def _minimal_push(opcode: int, data: bytes) -> bool:
    size = len(data)
    if size == 0:
        return opcode == op.OP_0
    if size == 1 and data[0] == 0x81:
        return opcode == op.OP_1NEGATE
    if size == 1 and 1 <= data[0] <= 16:
        return opcode == op.OP_1 + data[0] - 1
    if size <= 75:
        return opcode == size
    if size <= 0xFF:
        return opcode == op.OP_PUSHDATA1
    if size <= 0xFFFF:
        return opcode == op.OP_PUSHDATA2
    return opcode == op.OP_PUSHDATA4


def eval_script(
    script: bytes,
    stack: Iterable[bytes] = (),
    *,
    flags: ScriptFlags = ScriptFlags.NONE,
    checker: SignatureChecker | None = None,
    tapscript: bool = False,
    taproot_checker: TaprootChecker | None = None,
    sigop_budget: list[int] | None = None,
    tx_context: ScriptTransactionContext | None = None,
) -> list[bytes]:
    """Execute one script and return its resulting main stack."""
    if not tapscript and len(script) > MAX_SCRIPT_SIZE:
        raise ScriptError("script exceeds maximum size")
    main = list(stack)
    alt: list[bytes] = []
    if len(main) > MAX_STACK_SIZE or any(len(item) > MAX_SCRIPT_ELEMENT_SIZE for item in main):
        raise ScriptError("initial stack exceeds limits")
    conditions: list[bool] = []
    op_count = 0
    offset = 0
    last_code_separator = 0
    last_code_separator_position = 0xFFFFFFFF
    opcode_position = 0
    disabled = {
        op.OP_VERIF, op.OP_VERNOTIF, op.OP_CAT, op.OP_SUBSTR, op.OP_LEFT, op.OP_RIGHT,
        op.OP_INVERT, op.OP_AND, op.OP_OR, op.OP_XOR, op.OP_2MUL, op.OP_2DIV,
        op.OP_MUL, op.OP_DIV, op.OP_MOD, op.OP_LSHIFT, op.OP_RSHIFT,
    }

    while offset < len(script):
        instruction_start = offset
        opcode, pushed, offset = _read_op(script, offset)
        instruction_position = opcode_position
        opcode_position += 1
        if pushed is not None and len(pushed) > MAX_SCRIPT_ELEMENT_SIZE:
            raise ScriptError("pushed element exceeds 520 bytes")
        if opcode > op.OP_16:
            op_count += 1
            if not tapscript and op_count > MAX_OPS_PER_SCRIPT:
                raise ScriptError("operation count exceeds limit")
        if opcode in disabled and not tapscript:
            raise ScriptError("disabled opcode")

        executing = all(conditions)
        if pushed is not None:
            if executing:
                if flags & ScriptFlags.MINIMAL_DATA and not _minimal_push(opcode, pushed):
                    raise ScriptError("non-minimal data push")
                main.append(pushed)
                if len(main) + len(alt) > MAX_STACK_SIZE:
                    raise ScriptError("stack size exceeds limit")
            continue
        if opcode in (op.OP_IF, op.OP_NOTIF):
            value = False
            if executing:
                _require(main, 1)
                raw = main.pop()
                if (flags & ScriptFlags.MINIMAL_DATA or tapscript) and raw not in (b"", b"\x01"):
                    raise ScriptError("non-minimal IF argument")
                value = cast_to_bool(raw)
                if opcode == op.OP_NOTIF:
                    value = not value
            conditions.append(value)
            continue
        if opcode == op.OP_ELSE:
            if not conditions:
                raise ScriptError("ELSE without matching IF")
            conditions[-1] = not conditions[-1]
            continue
        if opcode == op.OP_ENDIF:
            if not conditions:
                raise ScriptError("ENDIF without matching IF")
            conditions.pop()
            continue
        if not executing:
            continue
        if opcode in (op.OP_RESERVED, op.OP_VER, op.OP_INVALIDOPCODE) or (
            opcode == op.OP_CHECKSIGADD and not tapscript
        ):
            raise ScriptError("reserved or unsupported opcode")
        if opcode == op.OP_1NEGATE:
            main.append(encode_script_num(-1))
        elif op.OP_1 <= opcode <= op.OP_16:
            main.append(encode_script_num(opcode - op.OP_1 + 1))
        elif opcode in (op.OP_NOP, op.OP_NOP1, *range(op.OP_NOP4, op.OP_NOP10 + 1)):
            if flags & ScriptFlags.DISCOURAGE_UPGRADABLE_NOPS:
                raise ScriptError("discouraged upgradeable NOP")
        elif opcode == op.OP_CHECKLOCKTIMEVERIFY:
            if not flags & ScriptFlags.CHECKLOCKTIMEVERIFY:
                if flags & ScriptFlags.DISCOURAGE_UPGRADABLE_NOPS:
                    raise ScriptError("discouraged CHECKLOCKTIMEVERIFY NOP")
            else:
                if tx_context is None:
                    raise ScriptError("CHECKLOCKTIMEVERIFY needs transaction context")
                _require(main, 1)
                lock_time = decode_script_num(
                    main[-1], max_size=5, minimal=bool(flags & ScriptFlags.MINIMAL_DATA)
                )
                tx = tx_context.transaction
                txin = tx.inputs[tx_context.input_index]
                if lock_time < 0:
                    raise ScriptError("negative CHECKLOCKTIMEVERIFY argument")
                if (lock_time < 500_000_000) != (tx.lock_time < 500_000_000):
                    raise ScriptError("CHECKLOCKTIMEVERIFY lock-time type mismatch")
                if lock_time > tx.lock_time or txin.sequence == 0xFFFFFFFF:
                    raise ScriptError("CHECKLOCKTIMEVERIFY check failed")
        elif opcode == op.OP_CHECKSEQUENCEVERIFY:
            if not flags & ScriptFlags.CHECKSEQUENCEVERIFY:
                if flags & ScriptFlags.DISCOURAGE_UPGRADABLE_NOPS:
                    raise ScriptError("discouraged CHECKSEQUENCEVERIFY NOP")
            else:
                if tx_context is None:
                    raise ScriptError("CHECKSEQUENCEVERIFY needs transaction context")
                _require(main, 1)
                sequence = decode_script_num(
                    main[-1], max_size=5, minimal=bool(flags & ScriptFlags.MINIMAL_DATA)
                )
                if sequence < 0:
                    raise ScriptError("negative CHECKSEQUENCEVERIFY argument")
                if not sequence & (1 << 31):
                    tx = tx_context.transaction
                    tx_sequence = tx.inputs[tx_context.input_index].sequence
                    type_flag = 1 << 22
                    sequence_mask = 0x0000FFFF
                    if tx.version < 2 or tx_sequence & (1 << 31):
                        raise ScriptError("CHECKSEQUENCEVERIFY disabled by transaction")
                    if (sequence & type_flag) != (tx_sequence & type_flag):
                        raise ScriptError("CHECKSEQUENCEVERIFY type mismatch")
                    if (sequence & sequence_mask) > (tx_sequence & sequence_mask):
                        raise ScriptError("CHECKSEQUENCEVERIFY check failed")
        elif opcode == op.OP_VERIFY:
            _require(main, 1)
            if not cast_to_bool(main.pop()):
                raise ScriptError("VERIFY failed")
        elif opcode == op.OP_RETURN:
            raise ScriptError("OP_RETURN executed")
        elif opcode == op.OP_TOALTSTACK:
            _require(main, 1)
            alt.append(main.pop())
        elif opcode == op.OP_FROMALTSTACK:
            _require(alt, 1)
            main.append(alt.pop())
        elif opcode == op.OP_2DROP:
            _require(main, 2)
            del main[-2:]
        elif opcode == op.OP_2DUP:
            _require(main, 2)
            main.extend(main[-2:])
        elif opcode == op.OP_3DUP:
            _require(main, 3)
            main.extend(main[-3:])
        elif opcode == op.OP_2OVER:
            _require(main, 4)
            main.extend(main[-4:-2])
        elif opcode == op.OP_2ROT:
            _require(main, 6)
            main.extend(main[-6:-4])
            del main[-8:-6]
        elif opcode == op.OP_2SWAP:
            _require(main, 4)
            main[-4:] = main[-2:] + main[-4:-2]
        elif opcode == op.OP_IFDUP:
            _require(main, 1)
            if cast_to_bool(main[-1]):
                main.append(main[-1])
        elif opcode == op.OP_DEPTH:
            main.append(encode_script_num(len(main)))
        elif opcode == op.OP_DROP:
            _require(main, 1)
            main.pop()
        elif opcode == op.OP_DUP:
            _require(main, 1)
            main.append(main[-1])
        elif opcode == op.OP_NIP:
            _require(main, 2)
            del main[-2]
        elif opcode == op.OP_OVER:
            _require(main, 2)
            main.append(main[-2])
        elif opcode in (op.OP_PICK, op.OP_ROLL):
            depth = _pop_num(main, flags)
            if depth < 0 or depth >= len(main):
                raise ScriptError("PICK/ROLL depth out of range")
            item = main[-depth - 1]
            if opcode == op.OP_ROLL:
                del main[-depth - 1]
            main.append(item)
        elif opcode == op.OP_ROT:
            _require(main, 3)
            main.append(main.pop(-3))
        elif opcode == op.OP_SWAP:
            _require(main, 2)
            main[-1], main[-2] = main[-2], main[-1]
        elif opcode == op.OP_TUCK:
            _require(main, 2)
            main.insert(len(main) - 2, main[-1])
        elif opcode == op.OP_SIZE:
            _require(main, 1)
            main.append(encode_script_num(len(main[-1])))
        elif opcode in (op.OP_EQUAL, op.OP_EQUALVERIFY):
            _require(main, 2)
            equal = main.pop() == main.pop()
            if opcode == op.OP_EQUALVERIFY:
                if not equal:
                    raise ScriptError("EQUALVERIFY failed")
            else:
                main.append(encode_script_num(int(equal)))
        elif opcode in (op.OP_1ADD, op.OP_1SUB, op.OP_NEGATE, op.OP_ABS, op.OP_NOT, op.OP_0NOTEQUAL):
            value = _pop_num(main, flags)
            result = {
                op.OP_1ADD: lambda: value + 1,
                op.OP_1SUB: lambda: value - 1,
                op.OP_NEGATE: lambda: -value,
                op.OP_ABS: lambda: abs(value),
                op.OP_NOT: lambda: int(value == 0),
                op.OP_0NOTEQUAL: lambda: int(value != 0),
            }[opcode]()
            main.append(encode_script_num(result))
        elif opcode in (
            op.OP_ADD, op.OP_SUB, op.OP_BOOLAND, op.OP_BOOLOR, op.OP_NUMEQUAL,
            op.OP_NUMEQUALVERIFY, op.OP_NUMNOTEQUAL, op.OP_LESSTHAN,
            op.OP_GREATERTHAN, op.OP_LESSTHANOREQUAL, op.OP_GREATERTHANOREQUAL,
            op.OP_MIN, op.OP_MAX,
        ):
            _require(main, 2)
            right = _pop_num(main, flags)
            left = _pop_num(main, flags)
            result = {
                op.OP_ADD: lambda: left + right,
                op.OP_SUB: lambda: left - right,
                op.OP_BOOLAND: lambda: int(left != 0 and right != 0),
                op.OP_BOOLOR: lambda: int(left != 0 or right != 0),
                op.OP_NUMEQUAL: lambda: int(left == right),
                op.OP_NUMEQUALVERIFY: lambda: int(left == right),
                op.OP_NUMNOTEQUAL: lambda: int(left != right),
                op.OP_LESSTHAN: lambda: int(left < right),
                op.OP_GREATERTHAN: lambda: int(left > right),
                op.OP_LESSTHANOREQUAL: lambda: int(left <= right),
                op.OP_GREATERTHANOREQUAL: lambda: int(left >= right),
                op.OP_MIN: lambda: min(left, right),
                op.OP_MAX: lambda: max(left, right),
            }[opcode]()
            if opcode == op.OP_NUMEQUALVERIFY:
                if not result:
                    raise ScriptError("NUMEQUALVERIFY failed")
            else:
                main.append(encode_script_num(result))
        elif opcode == op.OP_WITHIN:
            _require(main, 3)
            maximum = _pop_num(main, flags)
            minimum = _pop_num(main, flags)
            value = _pop_num(main, flags)
            main.append(encode_script_num(int(minimum <= value < maximum)))
        elif opcode in (op.OP_RIPEMD160, op.OP_SHA1, op.OP_SHA256, op.OP_HASH160, op.OP_HASH256):
            _require(main, 1)
            value = main.pop()
            if opcode == op.OP_RIPEMD160:
                digest = hashlib.new("ripemd160", value).digest()
            elif opcode == op.OP_SHA1:
                digest = hashlib.sha1(value).digest()
            elif opcode == op.OP_SHA256:
                digest = sha256(value)
            elif opcode == op.OP_HASH160:
                digest = hash160(value)
            else:
                digest = hash256(value)
            main.append(digest)
        elif opcode == op.OP_CODESEPARATOR:
            last_code_separator = offset
            last_code_separator_position = instruction_position
        elif opcode in (op.OP_CHECKSIG, op.OP_CHECKSIGVERIFY):
            _require(main, 2)
            pubkey = main.pop()
            signature = main.pop()
            code = script[last_code_separator:]
            if tapscript:
                if opcode in (op.OP_CHECKMULTISIG, op.OP_CHECKMULTISIGVERIFY):
                    raise ScriptError("CHECKMULTISIG is disabled in tapscript")
                if not pubkey:
                    raise ScriptError("empty public key in tapscript")
                if not signature:
                    success = False
                else:
                    if sigop_budget is not None:
                        sigop_budget[0] -= 50
                        if sigop_budget[0] < 0:
                            raise ScriptError("tapscript signature operation budget exceeded")
                    if len(pubkey) == 32:
                        success = bool(taproot_checker and taproot_checker(
                            signature, pubkey, last_code_separator_position
                        ))
                        if not success:
                            raise ScriptError("invalid tapscript signature")
                    elif flags & ScriptFlags.DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
                        raise ScriptError("discouraged future public-key type")
                    else:
                        success = True
            else:
                success = bool(checker and checker(signature, pubkey, code)) if signature else False
            if opcode == op.OP_CHECKSIGVERIFY:
                if not success:
                    raise ScriptError("CHECKSIGVERIFY failed")
            else:
                main.append(encode_script_num(int(success)))
        elif opcode in (op.OP_CHECKMULTISIG, op.OP_CHECKMULTISIGVERIFY) and tapscript:
            raise ScriptError("CHECKMULTISIG is disabled in tapscript")
        elif tapscript and opcode == op.OP_CHECKSIGADD:
            _require(main, 3)
            pubkey = main.pop()
            number = decode_script_num(main.pop(), minimal=bool(flags & ScriptFlags.MINIMAL_DATA), max_size=4)
            signature = main.pop()
            if not pubkey:
                raise ScriptError("empty public key in tapscript")
            success = False
            if signature:
                if sigop_budget is not None:
                    sigop_budget[0] -= 50
                    if sigop_budget[0] < 0:
                        raise ScriptError("tapscript signature operation budget exceeded")
                if len(pubkey) == 32:
                    success = bool(taproot_checker and taproot_checker(
                        signature, pubkey, last_code_separator_position
                    ))
                    if not success:
                        raise ScriptError("invalid tapscript signature")
                elif flags & ScriptFlags.DISCOURAGE_UPGRADABLE_PUBKEYTYPE:
                    raise ScriptError("discouraged future public-key type")
                else:
                    success = True
            main.append(encode_script_num(number + int(success)))
        elif opcode in (op.OP_CHECKMULTISIG, op.OP_CHECKMULTISIGVERIFY):
            key_count = _pop_num(main, flags)
            if not 0 <= key_count <= MAX_PUBKEYS_PER_MULTISIG:
                raise ScriptError("invalid multisig public-key count")
            op_count += key_count
            if op_count > MAX_OPS_PER_SCRIPT:
                raise ScriptError("operation count exceeds limit")
            _require(main, key_count + 1)
            pubkeys = [main.pop() for _ in range(key_count)][::-1]
            sig_count = _pop_num(main, flags)
            if not 0 <= sig_count <= key_count:
                raise ScriptError("invalid multisig signature count")
            _require(main, sig_count + 1)
            signatures = [main.pop() for _ in range(sig_count)][::-1]
            dummy = main.pop()
            if flags & ScriptFlags.NULL_DUMMY and dummy:
                raise ScriptError("multisig dummy argument is not null")
            matched = True
            key_index = sig_index = 0
            code = script[last_code_separator:]
            while matched and sig_index < sig_count:
                if checker is None or not checker(signatures[sig_index], pubkeys[key_index], code):
                    key_index += 1
                    if key_count - key_index < sig_count - sig_index:
                        matched = False
                else:
                    sig_index += 1
                    key_index += 1
            matched = matched and sig_index == sig_count
            if opcode == op.OP_CHECKMULTISIGVERIFY:
                if not matched:
                    raise ScriptError("CHECKMULTISIGVERIFY failed")
            else:
                main.append(encode_script_num(int(matched)))
        else:
            raise ScriptError(f"unsupported opcode 0x{opcode:02x} at {instruction_start}")

        if len(main) + len(alt) > MAX_STACK_SIZE:
            raise ScriptError("stack size exceeds limit")

    if conditions:
        raise ScriptError("unclosed conditional")
    return main


_OP_SUCCESS = {
    0x50, 0x62, *range(0x7E, 0x82), *range(0x83, 0x87), 0x89, 0x8A,
    0x8D, 0x8E, *range(0x95, 0x9A), *range(0xBB, 0xFF),
}


def eval_tapscript(
    script: bytes,
    stack: Iterable[bytes] = (),
    *,
    checker: TaprootChecker | None = None,
    sigop_budget: int = 50,
    flags: ScriptFlags = ScriptFlags.NONE,
) -> list[bytes]:
    """Execute tapscript, applying OP_SUCCESS and signature-budget rules."""
    initial_stack = list(stack)
    if len(initial_stack) > MAX_STACK_SIZE or any(len(item) > MAX_SCRIPT_ELEMENT_SIZE for item in initial_stack):
        raise ScriptError("initial tapscript stack exceeds limits")
    offset = 0
    while offset < len(script):
        opcode, pushed, offset = _read_op(script, offset)
        if pushed is None and opcode in _OP_SUCCESS:
            if flags & ScriptFlags.DISCOURAGE_OP_SUCCESS:
                raise ScriptError("discouraged OP_SUCCESS opcode")
            return [b"\x01"]
    budget = [sigop_budget]
    return eval_script(
        script,
        initial_stack,
        flags=flags,
        tapscript=True,
        taproot_checker=checker,
        sigop_budget=budget,
    )


def verify_script(
    script_sig: bytes,
    script_pubkey: bytes,
    *,
    checker: SignatureChecker | None = None,
    flags: ScriptFlags = ScriptFlags.NONE,
    tx_context: ScriptTransactionContext | None = None,
) -> bool:
    """Evaluate scriptSig then scriptPubKey and apply final stack rules."""
    is_p2sh = (
        len(script_pubkey) == 23
        and script_pubkey[0] == op.OP_HASH160
        and script_pubkey[1] == 20
        and script_pubkey[-1] == op.OP_EQUAL
    )
    if flags & ScriptFlags.P2SH and is_p2sh and not is_push_only(script_sig):
        raise ScriptError("scriptSig is not push-only")
    stack = eval_script(script_sig, checker=checker, flags=flags, tx_context=tx_context)
    saved_stack = stack.copy()
    stack = eval_script(script_pubkey, stack, checker=checker, flags=flags, tx_context=tx_context)
    if not stack or not cast_to_bool(stack[-1]):
        raise ScriptError("script evaluated to false")
    if flags & ScriptFlags.P2SH and is_p2sh:
        if not saved_stack:
            raise ScriptError("P2SH scriptSig does not provide a redeem script")
        redeem_script = saved_stack.pop()
        stack = eval_script(redeem_script, saved_stack, checker=checker, flags=flags, tx_context=tx_context)
        if not stack or not cast_to_bool(stack[-1]):
            raise ScriptError("redeem script evaluated to false")
    if flags & ScriptFlags.CLEAN_STACK and len(stack) != 1:
        raise ScriptError("clean-stack rule violated")
    return True
