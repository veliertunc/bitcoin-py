"""Bitcoin transaction data structures and wire serialization."""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from typing import BinaryIO

from bitcoin_core.crypto.hashes import hash256
from bitcoin_core.serialization.compact_size import read_compact_size, write_compact_size

MAX_MONEY = 21_000_000 * 100_000_000
MAX_SCRIPT_SIZE = 10_000_000
MAX_VECTOR_SIZE = 1_000_000
FINAL_SEQUENCE = 0xFFFFFFFF
NULL_INDEX = 0xFFFFFFFF


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise EOFError("unexpected end of transaction")
    return data


def _read_vector(stream: BinaryIO, *, limit: int) -> bytes:
    size = read_compact_size(stream)
    if size > limit:
        raise ValueError("transaction vector exceeds limit")
    return _read_exact(stream, size)


@dataclass(frozen=True, slots=True)
class OutPoint:
    """Reference to an output in a previous transaction."""

    txid: bytes = bytes(32)  # Raw uint256 bytes, in wire order.
    index: int = NULL_INDEX

    def __post_init__(self) -> None:
        if len(self.txid) != 32:
            raise ValueError("transaction id must contain 32 bytes")
        if not 0 <= self.index <= 0xFFFFFFFF:
            raise ValueError("output index must fit in uint32")

    @property
    def is_null(self) -> bool:
        return self.txid == bytes(32) and self.index == NULL_INDEX

    def serialize(self) -> bytes:
        return self.txid + self.index.to_bytes(4, "little")


@dataclass(frozen=True, slots=True)
class TxInput:
    """Transaction input, including its optional witness stack."""

    previous_output: OutPoint
    script_sig: bytes = b""
    sequence: int = FINAL_SEQUENCE
    witness: tuple[bytes, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not 0 <= self.sequence <= 0xFFFFFFFF:
            raise ValueError("input sequence must fit in uint32")
        if len(self.script_sig) > MAX_SCRIPT_SIZE:
            raise ValueError("scriptSig exceeds size limit")
        if len(self.witness) > MAX_VECTOR_SIZE or any(len(item) > MAX_SCRIPT_SIZE for item in self.witness):
            raise ValueError("witness exceeds size limit")

    def serialize(self) -> bytes:
        return (
            self.previous_output.serialize()
            + write_compact_size(len(self.script_sig))
            + self.script_sig
            + self.sequence.to_bytes(4, "little")
        )

    @property
    def has_witness(self) -> bool:
        return bool(self.witness)


@dataclass(frozen=True, slots=True)
class TxOutput:
    """Transaction output containing a value in satoshis and a locking script."""

    value: int
    script_pubkey: bytes = b""

    def __post_init__(self) -> None:
        if not -(1 << 63) <= self.value < (1 << 63):
            raise ValueError("output value must fit in int64")
        if len(self.script_pubkey) > MAX_SCRIPT_SIZE:
            raise ValueError("scriptPubKey exceeds size limit")

    def serialize(self) -> bytes:
        return (
            self.value.to_bytes(8, "little", signed=True)
            + write_compact_size(len(self.script_pubkey))
            + self.script_pubkey
        )


@dataclass(frozen=True, slots=True)
class Transaction:
    """Immutable transaction with legacy and witness serialization support."""

    version: int = 2
    inputs: tuple[TxInput, ...] = field(default_factory=tuple)
    outputs: tuple[TxOutput, ...] = field(default_factory=tuple)
    lock_time: int = 0

    def __post_init__(self) -> None:
        if not -(1 << 31) <= self.version < (1 << 31):
            raise ValueError("transaction version must fit in int32")
        if not 0 <= self.lock_time <= 0xFFFFFFFF:
            raise ValueError("lock time must fit in uint32")
        if len(self.inputs) > MAX_VECTOR_SIZE or len(self.outputs) > MAX_VECTOR_SIZE:
            raise ValueError("transaction input/output count exceeds limit")

    @property
    def has_witness(self) -> bool:
        return any(txin.has_witness for txin in self.inputs)

    def serialize(self, *, include_witness: bool = True) -> bytes:
        witness = include_witness and self.has_witness
        result = self.version.to_bytes(4, "little", signed=True)
        if witness:
            result += b"\x00\x01"
        result += write_compact_size(len(self.inputs))
        result += b"".join(txin.serialize() for txin in self.inputs)
        result += write_compact_size(len(self.outputs))
        result += b"".join(txout.serialize() for txout in self.outputs)
        if witness:
            for txin in self.inputs:
                result += write_compact_size(len(txin.witness))
                for item in txin.witness:
                    result += write_compact_size(len(item)) + item
        return result + self.lock_time.to_bytes(4, "little")

    @classmethod
    def deserialize(cls, raw: bytes, *, allow_witness: bool = True) -> Transaction:
        """Parse one transaction and reject non-canonical or trailing data."""
        stream = BytesIO(raw)
        version = int.from_bytes(_read_exact(stream, 4), "little", signed=True)
        input_count = read_compact_size(stream)
        witness_flag = 0
        if input_count == 0 and allow_witness:
            witness_flag = _read_exact(stream, 1)[0]
            if witness_flag:
                input_count = read_compact_size(stream)
                if input_count == 0:
                    raise ValueError("witness transaction must contain an input")
        if input_count > MAX_VECTOR_SIZE:
            raise ValueError("transaction input count exceeds limit")
        inputs = []
        for _ in range(input_count):
            txid = _read_exact(stream, 32)
            index = int.from_bytes(_read_exact(stream, 4), "little")
            script_sig = _read_vector(stream, limit=MAX_SCRIPT_SIZE)
            sequence = int.from_bytes(_read_exact(stream, 4), "little")
            inputs.append(TxInput(OutPoint(txid, index), script_sig, sequence))
        output_count = read_compact_size(stream)
        if output_count > MAX_VECTOR_SIZE:
            raise ValueError("transaction output count exceeds limit")
        outputs = []
        for _ in range(output_count):
            value = int.from_bytes(_read_exact(stream, 8), "little", signed=True)
            script = _read_vector(stream, limit=MAX_SCRIPT_SIZE)
            outputs.append(TxOutput(value, script))
        if witness_flag & 1:
            witnessed_inputs = []
            any_witness = False
            for txin in inputs:
                count = read_compact_size(stream)
                if count > MAX_VECTOR_SIZE:
                    raise ValueError("witness item count exceeds limit")
                witness = tuple(_read_vector(stream, limit=MAX_SCRIPT_SIZE) for _ in range(count))
                any_witness |= bool(witness)
                witnessed_inputs.append(TxInput(txin.previous_output, txin.script_sig, txin.sequence, witness))
            if not any_witness:
                raise ValueError("superfluous witness record")
            inputs = witnessed_inputs
            witness_flag ^= 1
        if witness_flag:
            raise ValueError("unknown transaction optional data flag")
        lock_time = int.from_bytes(_read_exact(stream, 4), "little")
        if stream.read(1):
            raise ValueError("trailing data after transaction")
        return cls(version, tuple(inputs), tuple(outputs), lock_time)

    @property
    def txid(self) -> bytes:
        """Raw double-SHA-256 transaction identifier (wire byte order)."""
        return hash256(self.serialize(include_witness=False))

    @property
    def wtxid(self) -> bytes:
        """Raw witness transaction identifier (wire byte order)."""
        return hash256(self.serialize(include_witness=True))

    @property
    def txid_hex(self) -> str:
        """Conventional displayed txid, with the digest bytes reversed."""
        return self.txid[::-1].hex()

    @property
    def wtxid_hex(self) -> str:
        """Conventional displayed wtxid, with the digest bytes reversed."""
        return self.wtxid[::-1].hex()

    def output_value(self) -> int:
        """Return the output sum, rejecting negative or out-of-range totals."""
        total = 0
        for txout in self.outputs:
            if not 0 <= txout.value <= MAX_MONEY or total + txout.value > MAX_MONEY:
                raise ValueError("transaction output value out of range")
            total += txout.value
        return total
