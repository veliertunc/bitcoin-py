"""Block headers, blocks, and transaction Merkle roots."""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO

from bitcoin_core.crypto.hashes import hash256
from bitcoin_core.primitives.transaction import MAX_VECTOR_SIZE, Transaction
from bitcoin_core.serialization.compact_size import read_compact_size, write_compact_size


@dataclass(frozen=True, slots=True)
class BlockHeader:
    """The fixed 80-byte header committed to by proof of work."""

    version: int
    previous_block: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int

    def __post_init__(self) -> None:
        if not -(1 << 31) <= self.version < (1 << 31):
            raise ValueError("block version must fit in int32")
        if len(self.previous_block) != 32 or len(self.merkle_root) != 32:
            raise ValueError("block hashes must contain 32 bytes")
        for name, value in (("timestamp", self.timestamp), ("bits", self.bits), ("nonce", self.nonce)):
            if not 0 <= value <= 0xFFFFFFFF:
                raise ValueError(f"{name} must fit in uint32")

    def serialize(self) -> bytes:
        return (
            self.version.to_bytes(4, "little", signed=True)
            + self.previous_block
            + self.merkle_root
            + self.timestamp.to_bytes(4, "little")
            + self.bits.to_bytes(4, "little")
            + self.nonce.to_bytes(4, "little")
        )

    @classmethod
    def deserialize(cls, raw: bytes) -> BlockHeader:
        if len(raw) != 80:
            raise ValueError("block header must be exactly 80 bytes")
        return cls(
            int.from_bytes(raw[0:4], "little", signed=True),
            raw[4:36],
            raw[36:68],
            int.from_bytes(raw[68:72], "little"),
            int.from_bytes(raw[72:76], "little"),
            int.from_bytes(raw[76:80], "little"),
        )

    @property
    def block_hash(self) -> bytes:
        """Return the raw hash bytes in wire order."""
        return hash256(self.serialize())

    @property
    def block_hash_hex(self) -> str:
        """Return the conventional displayed block hash."""
        return self.block_hash[::-1].hex()


@dataclass(frozen=True, slots=True)
class Block:
    """Block header and ordered transaction list."""

    header: BlockHeader
    transactions: tuple[Transaction, ...] = field(default_factory=tuple)

    def serialize(self) -> bytes:
        return self.header.serialize() + write_compact_size(len(self.transactions)) + b"".join(
            tx.serialize() for tx in self.transactions
        )

    @classmethod
    def deserialize(cls, raw: bytes) -> Block:
        stream = BytesIO(raw)
        header = BlockHeader.deserialize(stream.read(80))
        count = read_compact_size(stream)
        if count == 0 or count > MAX_VECTOR_SIZE:
            raise ValueError("block transaction count is out of range")
        transactions = []
        for _ in range(count):
            # Transaction framing is not length-prefixed. Parse fields directly from
            # the shared stream, then reuse the transaction parser on the consumed bytes.
            transactions.append(_read_transaction(stream))
        if stream.read(1):
            raise ValueError("trailing data after block")
        return cls(header, tuple(transactions))

    @property
    def merkle_root(self) -> bytes:
        """Compute the txid Merkle root in raw wire byte order."""
        return merkle_root([tx.txid for tx in self.transactions])[0]


def merkle_root(leaves: list[bytes] | tuple[bytes, ...]) -> tuple[bytes, bool]:
    """Return (root, mutated), following Bitcoin's duplicate-last tree rule."""
    if not leaves:
        return bytes(32), False
    if any(len(leaf) != 32 for leaf in leaves):
        raise ValueError("Merkle tree leaves must contain 32 bytes")
    level = list(leaves)
    mutated = False
    while len(level) > 1:
        for index in range(0, len(level) - 1, 2):
            if level[index] == level[index + 1]:
                mutated = True
        if len(level) & 1:
            level.append(level[-1])
        level = [hash256(level[index] + level[index + 1]) for index in range(0, len(level), 2)]
    return level[0], mutated


def _read_transaction(stream: BytesIO) -> Transaction:
    """Read a transaction from a block stream without an external size prefix."""
    start = stream.tell()
    version = stream.read(4)
    if len(version) != 4:
        raise EOFError("truncated transaction version in block")
    count_prefix = stream.read(1)
    if not count_prefix:
        raise EOFError("truncated transaction input count in block")
    # Reconstruct enough framing to learn the transaction boundary. CompactSize
    # values and scripts/witness items are consumed through bounded exact reads.
    marker = count_prefix[0]
    if marker == 0:
        flag = stream.read(1)
        if len(flag) != 1:
            raise EOFError("truncated transaction witness flag in block")
        input_count = read_compact_size(stream)
        witness_flag = flag[0]
    else:
        stream.seek(-1, 1)
        input_count = read_compact_size(stream)
        witness_flag = 0
    if input_count > MAX_VECTOR_SIZE:
        raise ValueError("transaction input count exceeds limit")
    for _ in range(input_count):
        _consume(stream, 36)
        _consume_vector(stream)
        _consume(stream, 4)
    output_count = read_compact_size(stream)
    if output_count > MAX_VECTOR_SIZE:
        raise ValueError("transaction output count exceeds limit")
    for _ in range(output_count):
        _consume(stream, 8)
        _consume_vector(stream)
    if witness_flag & 1:
        for _ in range(input_count):
            item_count = read_compact_size(stream)
            if item_count > MAX_VECTOR_SIZE:
                raise ValueError("witness item count exceeds limit")
            for _ in range(item_count):
                _consume_vector(stream)
    _consume(stream, 4)
    end = stream.tell()
    stream.seek(start)
    encoded = stream.read(end - start)
    return Transaction.deserialize(encoded)


def _consume(stream: BytesIO, length: int) -> None:
    if len(stream.read(length)) != length:
        raise EOFError("truncated transaction in block")


def _consume_vector(stream: BytesIO) -> None:
    length = read_compact_size(stream)
    if length > 10_000_000:
        raise ValueError("transaction vector exceeds size limit")
    _consume(stream, length)
