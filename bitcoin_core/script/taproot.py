"""BIP341 Taproot signature hashing and transaction-bound Schnorr checks."""

from __future__ import annotations

from dataclasses import dataclass

from bitcoin_core.crypto.hashes import sha256
from bitcoin_core.crypto.schnorr import tagged_hash, verify_schnorr
from bitcoin_core.crypto.secp256k1 import GENERATOR, ORDER, _point_add, _point_mul
from bitcoin_core.primitives.transaction import Transaction, TxOutput
from bitcoin_core.serialization.compact_size import write_compact_size

SIGHASH_DEFAULT = 0
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80
_VALID_HASH_TYPES = {0, 1, 2, 3, 0x81, 0x82, 0x83}


@dataclass(frozen=True, slots=True)
class SpentOutput:
    """Value and locking script of an input's spent output."""

    value: int
    script_pubkey: bytes

    def serialize_script(self) -> bytes:
        return write_compact_size(len(self.script_pubkey)) + self.script_pubkey


def tapleaf_hash(script: bytes, *, leaf_version: int = 0xC0) -> bytes:
    """Compute the BIP341 TapLeaf tagged hash."""
    if not 0 <= leaf_version <= 0xFE or leaf_version & 1:
        raise ValueError("TapLeaf version must be an even byte")
    return tagged_hash("TapLeaf", bytes((leaf_version,)) + write_compact_size(len(script)) + script)


def verify_taproot_commitment(script_pubkey: bytes, script: bytes, control_block: bytes) -> bytes:
    """Validate a tapscript control block and return its 32-byte TapLeaf hash."""
    if len(script_pubkey) != 34 or script_pubkey[:2] != b"\x51\x20":
        raise ValueError("scriptPubKey is not a Taproot witness-v1 program")
    if len(control_block) < 33 or (len(control_block) - 33) % 32 or len(control_block) > 33 + 32 * 128:
        raise ValueError("invalid Taproot control-block length")
    control = control_block[0]
    leaf_version = control & 0xFE
    parity = control & 1
    internal_key = control_block[1:33]
    from bitcoin_core.crypto.schnorr import _lift_x

    point = _lift_x(int.from_bytes(internal_key, "big"))
    if point is None:
        raise ValueError("invalid Taproot internal key")
    merkle_root = tapleaf_hash(script, leaf_version=leaf_version)
    for offset in range(33, len(control_block), 32):
        sibling = control_block[offset : offset + 32]
        branch = min(merkle_root, sibling) + max(merkle_root, sibling)
        merkle_root = tagged_hash("TapBranch", branch)
    tweak = int.from_bytes(tagged_hash("TapTweak", internal_key + merkle_root), "big")
    if tweak >= ORDER:
        raise ValueError("Taproot tweak is out of range")
    output_point = _point_add(point, _point_mul(tweak, GENERATOR))
    if output_point is None or output_point[1] & 1 != parity:
        raise ValueError("Taproot control-block parity mismatch")
    if output_point[0].to_bytes(32, "big") != script_pubkey[2:]:
        raise ValueError("Taproot control block does not commit to output key")
    return tapleaf_hash(script, leaf_version=leaf_version)


def taproot_signature_hash(
    tx: Transaction,
    input_index: int,
    spent_outputs: tuple[SpentOutput, ...] | list[SpentOutput],
    *,
    hash_type: int = SIGHASH_DEFAULT,
    annex: bytes | None = None,
    ext_flag: int = 0,
    tapleaf: bytes | None = None,
    key_version: int = 0,
    code_separator_position: int = 0xFFFFFFFF,
) -> bytes:
    """Compute the BIP341 TapSighash digest for key or script path spending."""
    if hash_type not in _VALID_HASH_TYPES:
        raise ValueError("invalid Taproot sighash type")
    if not 0 <= input_index < len(tx.inputs):
        raise ValueError("Taproot input index out of range")
    if len(spent_outputs) != len(tx.inputs):
        raise ValueError("Taproot sighash requires every spent output")
    if annex is not None and (not annex or annex[0] != 0x50):
        raise ValueError("Taproot annex must begin with 0x50")
    if not 0 <= ext_flag <= 127:
        raise ValueError("Taproot extension flag must fit in 7 bits")
    if ext_flag == 1 and (tapleaf is None or len(tapleaf) != 32):
        raise ValueError("script-path sighash requires a 32-byte TapLeaf hash")
    if not 0 <= key_version <= 255 or not 0 <= code_separator_position <= 0xFFFFFFFF:
        raise ValueError("invalid tapscript extension data")

    anyone = bool(hash_type & SIGHASH_ANYONECANPAY)
    base_type = SIGHASH_ALL if hash_type == SIGHASH_DEFAULT else hash_type & 3
    message = bytearray((hash_type,))
    message.extend(tx.version.to_bytes(4, "little", signed=True))
    message.extend(tx.lock_time.to_bytes(4, "little"))
    if not anyone:
        message.extend(sha256(b"".join(txin.previous_output.serialize() for txin in tx.inputs)))
        message.extend(sha256(b"".join(output.value.to_bytes(8, "little", signed=True) for output in spent_outputs)))
        message.extend(sha256(b"".join(output.serialize_script() for output in spent_outputs)))
        message.extend(sha256(b"".join(txin.sequence.to_bytes(4, "little") for txin in tx.inputs)))
    if base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        message.extend(sha256(b"".join(output.serialize() for output in tx.outputs)))
    spend_type = ext_flag * 2 + (1 if annex is not None else 0)
    message.append(spend_type)
    if anyone:
        txin = tx.inputs[input_index]
        spent = spent_outputs[input_index]
        message.extend(txin.previous_output.serialize())
        message.extend(spent.value.to_bytes(8, "little", signed=True))
        message.extend(spent.serialize_script())
        message.extend(txin.sequence.to_bytes(4, "little"))
    else:
        message.extend(input_index.to_bytes(4, "little"))
    if annex is not None:
        message.extend(sha256(write_compact_size(len(annex)) + annex))
    if base_type == SIGHASH_SINGLE:
        if input_index >= len(tx.outputs):
            raise ValueError("SIGHASH_SINGLE input has no corresponding output")
        message.extend(sha256(tx.outputs[input_index].serialize()))
    if ext_flag == 1:
        message.extend(tapleaf)
        message.append(key_version)
        message.extend(code_separator_position.to_bytes(4, "little"))
    return tagged_hash("TapSighash", b"\x00" + message)


@dataclass(frozen=True, slots=True)
class TaprootSignatureChecker:
    """Verify key-path or tapscript Schnorr signatures for one transaction input."""

    transaction: Transaction
    input_index: int
    spent_outputs: tuple[SpentOutput, ...]
    annex: bytes | None = None
    ext_flag: int = 0
    tapleaf: bytes | None = None
    key_version: int = 0
    code_separator_position: int = 0xFFFFFFFF

    def __call__(self, signature: bytes, public_key: bytes) -> bool:
        if len(signature) == 64:
            hash_type = SIGHASH_DEFAULT
            schnorr_signature = signature
        elif len(signature) == 65 and signature[-1] != SIGHASH_DEFAULT:
            hash_type = signature[-1]
            schnorr_signature = signature[:64]
        else:
            return False
        try:
            digest = taproot_signature_hash(
                self.transaction,
                self.input_index,
                self.spent_outputs,
                hash_type=hash_type,
                annex=self.annex,
                ext_flag=self.ext_flag,
                tapleaf=self.tapleaf,
                key_version=self.key_version,
                code_separator_position=self.code_separator_position,
            )
        except ValueError:
            return False
        return verify_schnorr(digest, schnorr_signature, public_key)


def verify_taproot_keypath(
    tx: Transaction,
    input_index: int,
    spent_outputs: tuple[SpentOutput, ...] | list[SpentOutput],
    witness: tuple[bytes, ...] | list[bytes],
) -> bool:
    """Verify a key-path witness against the spent output's Taproot program."""
    if not 0 <= input_index < len(tx.inputs) or len(spent_outputs) != len(tx.inputs):
        return False
    witness_items = list(witness)
    annex = None
    if len(witness_items) >= 2 and witness_items[-1].startswith(b"\x50"):
        annex = witness_items.pop()
    if len(witness_items) != 1:
        return False
    script_pubkey = spent_outputs[input_index].script_pubkey
    if len(script_pubkey) != 34 or script_pubkey[:2] != b"\x51\x20":
        return False
    checker = TaprootSignatureChecker(tx, input_index, tuple(spent_outputs), annex=annex)
    return checker(witness_items[0], script_pubkey[2:])
