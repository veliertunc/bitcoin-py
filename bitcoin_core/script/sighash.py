"""Legacy and BIP143 signature hashing and transaction-bound checkers."""

from __future__ import annotations

from dataclasses import dataclass

from bitcoin_core.crypto.hashes import hash256
from bitcoin_core.crypto.secp256k1 import verify_ecdsa
from bitcoin_core.primitives.transaction import OutPoint, Transaction, TxInput, TxOutput
from bitcoin_core.script.interpreter import SignatureChecker
from bitcoin_core.serialization.compact_size import write_compact_size

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80
ONE_HASH = b"\x01" + bytes(31)


def _serialize_input(txin: TxInput, script: bytes, sequence: int | None = None) -> bytes:
    return (
        txin.previous_output.serialize()
        + write_compact_size(len(script))
        + script
        + (txin.sequence if sequence is None else sequence).to_bytes(4, "little")
    )


def _serialize_output(txout: TxOutput) -> bytes:
    return txout.serialize()


def _remove_codeseparators(script: bytes) -> bytes:
    """Remove OP_CODESEPARATOR opcodes without changing pushed data."""
    result = bytearray()
    offset = 0
    while offset < len(script):
        start = offset
        opcode = script[offset]
        offset += 1
        if opcode <= 75:
            size = opcode
        elif opcode == 0x4C:
            if offset + 1 > len(script):
                return script
            size = script[offset]
            offset += 1
        elif opcode == 0x4D:
            if offset + 2 > len(script):
                return script
            size = int.from_bytes(script[offset : offset + 2], "little")
            offset += 2
        elif opcode == 0x4E:
            if offset + 4 > len(script):
                return script
            size = int.from_bytes(script[offset : offset + 4], "little")
            offset += 4
        else:
            if opcode != 0xAB:
                result.append(opcode)
            continue
        if offset + size > len(script):
            return script
        result.extend(script[start : offset + size])
        offset += size
    return bytes(result)


def _find_and_delete(script: bytes, signature: bytes) -> bytes:
    """Delete canonical pushes of a signature, as legacy SignatureHash requires."""
    if len(signature) <= 75:
        needle = bytes((len(signature),)) + signature
    elif len(signature) <= 0xFF:
        needle = b"\x4c" + bytes((len(signature),)) + signature
    elif len(signature) <= 0xFFFF:
        needle = b"\x4d" + len(signature).to_bytes(2, "little") + signature
    else:
        needle = b"\x4e" + len(signature).to_bytes(4, "little") + signature
    return script.replace(needle, b"")


def legacy_signature_hash(tx: Transaction, input_index: int, script_code: bytes, hash_type: int, signature: bytes = b"") -> bytes:
    """Compute pre-SegWit SignatureHash for a transaction input."""
    base_type = hash_type & 0x1F
    if input_index < 0 or input_index >= len(tx.inputs):
        return ONE_HASH
    if base_type == SIGHASH_SINGLE and input_index >= len(tx.outputs):
        return ONE_HASH
    script_code = _remove_codeseparators(_find_and_delete(script_code, signature))
    anyone = bool(hash_type & SIGHASH_ANYONECANPAY)
    if anyone:
        inputs = [_serialize_input(tx.inputs[input_index], script_code)]
    else:
        inputs = [
            _serialize_input(
                txin,
                script_code if index == input_index else b"",
                0 if index != input_index and base_type in (SIGHASH_NONE, SIGHASH_SINGLE) else None,
            )
            for index, txin in enumerate(tx.inputs)
        ]
    if base_type == SIGHASH_NONE:
        outputs: list[bytes] = []
    elif base_type == SIGHASH_SINGLE:
        outputs = [TxOutput(-1).serialize()] * input_index + [_serialize_output(tx.outputs[input_index])]
    else:
        outputs = [_serialize_output(output) for output in tx.outputs]
    preimage = (
        tx.version.to_bytes(4, "little", signed=True)
        + write_compact_size(len(inputs))
        + b"".join(inputs)
        + write_compact_size(len(outputs))
        + b"".join(outputs)
        + tx.lock_time.to_bytes(4, "little")
        + hash_type.to_bytes(4, "little")
    )
    return hash256(preimage)


def witness_v0_signature_hash(
    tx: Transaction,
    input_index: int,
    script_code: bytes,
    amount: int,
    hash_type: int,
) -> bytes:
    """Compute BIP143 SignatureHash for a SegWit v0 input."""
    if input_index < 0 or input_index >= len(tx.inputs):
        return ONE_HASH
    base_type = hash_type & 0x1F
    anyone = bool(hash_type & SIGHASH_ANYONECANPAY)
    zero = bytes(32)
    hash_prevouts = zero
    hash_sequence = zero
    hash_outputs = zero
    if not anyone:
        hash_prevouts = hash256(b"".join(txin.previous_output.serialize() for txin in tx.inputs))
    if not anyone and base_type not in (SIGHASH_SINGLE, SIGHASH_NONE):
        hash_sequence = hash256(b"".join(txin.sequence.to_bytes(4, "little") for txin in tx.inputs))
    if base_type not in (SIGHASH_SINGLE, SIGHASH_NONE):
        hash_outputs = hash256(b"".join(_serialize_output(output) for output in tx.outputs))
    elif base_type == SIGHASH_SINGLE and input_index < len(tx.outputs):
        hash_outputs = hash256(_serialize_output(tx.outputs[input_index]))
    txin = tx.inputs[input_index]
    preimage = (
        tx.version.to_bytes(4, "little", signed=True)
        + hash_prevouts
        + hash_sequence
        + txin.previous_output.serialize()
        + write_compact_size(len(script_code))
        + script_code
        + amount.to_bytes(8, "little", signed=True)
        + txin.sequence.to_bytes(4, "little")
        + hash_outputs
        + tx.lock_time.to_bytes(4, "little")
        + hash_type.to_bytes(4, "little")
    )
    return hash256(preimage)


@dataclass(frozen=True, slots=True)
class TransactionSignatureChecker:
    """ECDSA checker bound to a transaction input and optional prevout amount."""

    transaction: Transaction
    input_index: int
    amount: int | None = None
    witness_v0: bool = False
    strict_hash_type: bool = False
    low_s: bool = False
    strict_der: bool = True
    compressed_pubkeys_only: bool = False

    def __call__(self, signature: bytes, public_key: bytes, script_code: bytes) -> bool:
        if self.compressed_pubkeys_only and len(public_key) != 33:
            return False
        if len(signature) < 2:
            return False
        encoded_signature, hash_type = signature[:-1], signature[-1]
        if self.strict_hash_type and ((hash_type & 0x1F) not in (1, 2, 3) or (hash_type & ~0x83)):
            return False
        if self.witness_v0:
            if self.amount is None:
                return False
            digest = witness_v0_signature_hash(
                self.transaction, self.input_index, script_code, self.amount, hash_type
            )
        else:
            digest = legacy_signature_hash(
                self.transaction, self.input_index, script_code, hash_type, signature
            )
        return verify_ecdsa(
            digest,
            encoded_signature,
            public_key,
            low_s=self.low_s,
            strict_der=self.strict_der,
        )
