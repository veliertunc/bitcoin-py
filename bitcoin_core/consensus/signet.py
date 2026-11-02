"""BIP325 signet block-solution extraction and challenge verification."""

from __future__ import annotations

from dataclasses import replace
from io import BytesIO

from bitcoin_core.crypto.hashes import hash256
from bitcoin_core.primitives.block import Block, merkle_root
from bitcoin_core.primitives.transaction import OutPoint, Transaction, TxInput, TxOutput
from bitcoin_core.script.interpreter import ScriptFlags
from bitcoin_core.script.validation import verify_transaction_input
from bitcoin_core.serialization.compact_size import read_compact_size

SIGNET_HEADER = bytes.fromhex("ecc7daa2")
WITNESS_COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")
MAX_SIGNET_SOLUTION_SIZE = 100_000


def _push(data: bytes) -> bytes:
    """Encode one minimally pushed script element."""
    if not data:
        return b"\x00"
    if len(data) == 1 and data[0] == 0x81:
        return b"\x4f"
    if len(data) == 1 and 1 <= data[0] <= 16:
        return bytes((0x50 + data[0],))
    if len(data) <= 75:
        return bytes((len(data),)) + data
    if len(data) <= 0xFF:
        return b"\x4c" + bytes((len(data),)) + data
    if len(data) <= 0xFFFF:
        return b"\x4d" + len(data).to_bytes(2, "little") + data
    return b"\x4e" + len(data).to_bytes(4, "little") + data


def _read_push(script: bytes, position: int) -> tuple[int, bytes | None, int]:
    if position >= len(script):
        raise ValueError("truncated signet commitment script")
    opcode = script[position]
    position += 1
    if opcode == 0:
        return opcode, b"", position
    if opcode == 0x4F:
        return opcode, b"\x81", position
    if 0x51 <= opcode <= 0x60:
        return opcode, bytes((opcode - 0x50,)), position
    if opcode <= 75:
        size = opcode
    elif opcode == 0x4C:
        if position >= len(script):
            raise ValueError("truncated signet PUSHDATA1")
        size, position = script[position], position + 1
    elif opcode == 0x4D:
        if position + 2 > len(script):
            raise ValueError("truncated signet PUSHDATA2")
        size = int.from_bytes(script[position : position + 2], "little")
        position += 2
    elif opcode == 0x4E:
        if position + 4 > len(script):
            raise ValueError("truncated signet PUSHDATA4")
        size = int.from_bytes(script[position : position + 4], "little")
        position += 4
    else:
        return opcode, None, position
    end = position + size
    if end > len(script):
        raise ValueError("signet push extends beyond commitment script")
    return opcode, script[position:end], end


def _strip_solution(script: bytes) -> tuple[bytes, bytes | None]:
    output = bytearray()
    solution = None
    position = 0
    while position < len(script):
        opcode, data, next_position = _read_push(script, position)
        if data is None:
            output.append(opcode)
        else:
            if solution is None and len(data) > len(SIGNET_HEADER) and data.startswith(SIGNET_HEADER):
                solution = data[len(SIGNET_HEADER) :]
                data = SIGNET_HEADER
            output.extend(_push(data))
        position = next_position
    return bytes(output), solution


def _decode_solution(solution: bytes) -> tuple[bytes, tuple[bytes, ...]]:
    if len(solution) > MAX_SIGNET_SOLUTION_SIZE:
        raise ValueError("signet solution exceeds maximum size")
    stream = BytesIO(solution)
    script_length = read_compact_size(stream)
    if script_length > 10_000:
        raise ValueError("signet scriptSig exceeds maximum size")
    script_sig = stream.read(script_length)
    if len(script_sig) != script_length:
        raise ValueError("truncated signet scriptSig")
    witness_count = read_compact_size(stream)
    if witness_count > 1_000:
        raise ValueError("signet witness has too many elements")
    witness = []
    for _ in range(witness_count):
        length = read_compact_size(stream)
        if length > 10_000:
            raise ValueError("signet witness element is too large")
        item = stream.read(length)
        if len(item) != length:
            raise ValueError("truncated signet witness element")
        witness.append(item)
    if stream.read(1):
        raise ValueError("trailing bytes in signet solution")
    return script_sig, tuple(witness)


def check_signet_block_solution(block: Block, challenge: bytes) -> bool:
    """Validate the BIP325 challenge solution committed in the coinbase output."""
    if not challenge:
        return True
    if not block.transactions:
        return False
    coinbase = block.transactions[0]
    commitment_index = None
    for index, output in enumerate(coinbase.outputs):
        script = output.script_pubkey
        if len(script) >= 38 and script.startswith(WITNESS_COMMITMENT_PREFIX):
            commitment_index = index
    if commitment_index is None:
        return False
    outputs = list(coinbase.outputs)
    try:
        stripped_script, solution = _strip_solution(outputs[commitment_index].script_pubkey)
    except ValueError:
        return False
    outputs[commitment_index] = TxOutput(outputs[commitment_index].value, stripped_script)
    modified_coinbase = replace(coinbase, outputs=tuple(outputs))
    root, _mutated = merkle_root(
        [modified_coinbase.txid, *(tx.txid for tx in block.transactions[1:])]
    )
    header_data = (
        block.header.version.to_bytes(4, "little", signed=True)
        + block.header.previous_block
        + root
        + block.header.timestamp.to_bytes(4, "little")
    )

    solution_script = b""
    solution_witness: tuple[bytes, ...] = ()
    if solution is not None:
        try:
            solution_script, solution_witness = _decode_solution(solution)
        except (EOFError, ValueError):
            return False

    to_spend = Transaction(
        version=0,
        inputs=(TxInput(OutPoint(), b"\x00" + _push(header_data), sequence=0),),
        outputs=(TxOutput(0, challenge),),
        lock_time=0,
    )
    to_sign = Transaction(
        version=0,
        inputs=(
            TxInput(OutPoint(to_spend.txid, 0), solution_script, sequence=0, witness=solution_witness),
        ),
        outputs=(TxOutput(0, b"\x6a"),),
        lock_time=0,
    )
    # BIP325 uses P2SH, SegWit, strict DER signatures, and NULLDUMMY for the challenge.
    flags = ScriptFlags.P2SH | ScriptFlags.WITNESS | ScriptFlags.NULL_DUMMY | ScriptFlags.DERSIG
    prevout = type("SignetCoin", (), {"value": 0, "script_pubkey": challenge})()
    return verify_transaction_input(to_sign, 0, prevout, (prevout,), flags=flags)

