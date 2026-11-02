"""BIP 157/158 basic compact block filters."""

from __future__ import annotations

from io import BytesIO

from bitcoin_core.consensus.chainstate import BlockUndo
from bitcoin_core.crypto.hashes import hash256
from bitcoin_core.crypto.siphash import siphash24
from bitcoin_core.primitives.block import Block
from bitcoin_core.serialization.compact_size import read_compact_size, write_compact_size

BASIC_FILTER_P = 19
BASIC_FILTER_M = 784_931
MAX_BASIC_FILTER_ELEMENTS = 4_000_000


def basic_filter_elements(block: Block, undo: BlockUndo) -> set[bytes]:
    """Collect the unique output and spent-output scripts used by a basic filter."""
    elements = {
        output.script_pubkey
        for transaction in block.transactions
        for output in transaction.outputs
        if output.script_pubkey and output.script_pubkey[0] != 0x6A
    }
    elements.update(coin.script_pubkey for _outpoint, coin in undo.spent if coin.script_pubkey)
    return elements


def encode_basic_filter(block_hash: bytes, elements: set[bytes]) -> bytes:
    """Encode a BIP158 basic Golomb-coded set for one block."""
    if len(block_hash) != 32:
        raise ValueError("block hash must contain 32 bytes")
    count = len(elements)
    if count >= 1 << 32:
        raise ValueError("compact filter element count must be less than 2^32")
    encoded = bytearray(write_compact_size(count))
    if count == 0:
        return bytes(encoded)
    key = block_hash[:16]
    value_range = count * BASIC_FILTER_M
    values = sorted((siphash24(key, element) * value_range) >> 64 for element in elements)

    bit_writer = _BitWriter(encoded)
    last_value = 0
    for value in values:
        delta = value - last_value
        quotient, remainder = divmod(delta, 1 << BASIC_FILTER_P)
        bit_writer.write_ones(quotient)
        bit_writer.write_bit(0)
        bit_writer.write_bits(remainder, BASIC_FILTER_P)
        last_value = value
    bit_writer.flush()
    return bytes(encoded)


def match_basic_filter(block_hash: bytes, encoded_filter: bytes, elements: set[bytes]) -> bool:
    """Validate and test a BIP158 basic filter for any supplied scripts."""
    if len(block_hash) != 32:
        raise ValueError("block hash must contain 32 bytes")
    stream = BytesIO(encoded_filter)
    count = read_compact_size(stream)
    if count > MAX_BASIC_FILTER_ELEMENTS:
        raise ValueError("compact filter element count exceeds implementation limit")
    bitstream = stream.read()
    if count == 0:
        if bitstream:
            raise ValueError("empty compact filter contains encoded values")
        return False

    bit_reader = _BitReader(bitstream)
    value = 0
    max_quotient = ((1 << 64) - 1) >> BASIC_FILTER_P
    value_range = count * BASIC_FILTER_M
    key = block_hash[:16]
    queries = sorted({(siphash24(key, item) * value_range) >> 64 for item in elements})
    query_position = 0
    matched = False
    for _ in range(count):
        quotient = 0
        while bit_reader.read_bit():
            quotient += 1
            if quotient > max_quotient:
                raise ValueError("compact filter Golomb value overflows uint64")
        remainder = bit_reader.read_bits(BASIC_FILTER_P)
        delta = (quotient << BASIC_FILTER_P) | remainder
        if value + delta >= 1 << 64:
            raise ValueError("compact filter values overflow uint64")
        value += delta
        if value >= value_range:
            raise ValueError("compact filter value exceeds the encoded range")
        while query_position < len(queries) and queries[query_position] < value:
            query_position += 1
        if query_position < len(queries) and queries[query_position] == value:
            matched = True
            query_position += 1
    if (bit_reader.position + 7) // 8 != len(bitstream):
        raise ValueError("compact filter contains trailing data")

    return matched


def compact_filter_hash(encoded_filter: bytes) -> bytes:
    """Return the internal byte-order hash of an encoded compact filter."""
    return hash256(encoded_filter)


def compact_filter_header(filter_hash: bytes, previous_header: bytes = bytes(32)) -> bytes:
    """Return the BIP157 chained filter header in internal byte order."""
    if len(filter_hash) != 32 or len(previous_header) != 32:
        raise ValueError("filter hashes and headers must contain 32 bytes")
    return hash256(filter_hash + previous_header)


class _BitWriter:
    """Write bits most-significant-bit first, as the Core compact filter codec does."""

    __slots__ = ("_output", "_byte", "_used")

    def __init__(self, output: bytearray):
        self._output = output
        self._byte = 0
        self._used = 0

    def write_bit(self, value: int) -> None:
        self._byte |= (value & 1) << (7 - self._used)
        self._used += 1
        if self._used == 8:
            self._output.append(self._byte)
            self._byte = 0
            self._used = 0

    def write_ones(self, count: int) -> None:
        while count >= 8 - self._used and self._used:
            take = 8 - self._used
            for _ in range(take):
                self.write_bit(1)
            count -= take
        while count >= 8:
            self._output.append(0xFF)
            count -= 8
        for _ in range(count):
            self.write_bit(1)

    def write_bits(self, value: int, count: int) -> None:
        for position in range(count - 1, -1, -1):
            self.write_bit((value >> position) & 1)

    def flush(self) -> None:
        if self._used:
            self._output.append(self._byte)
            self._byte = 0
            self._used = 0


class _BitReader:
    """Read a compact-filter bitstream most-significant-bit first."""

    __slots__ = ("_data", "position")

    def __init__(self, data: bytes):
        self._data = data
        self.position = 0

    def read_bit(self) -> int:
        if self.position >= len(self._data) * 8:
            raise ValueError("truncated compact filter bitstream")
        byte_index, bit_index = divmod(self.position, 8)
        self.position += 1
        return (self._data[byte_index] >> (7 - bit_index)) & 1

    def read_bits(self, count: int) -> int:
        value = 0
        for _ in range(count):
            value = (value << 1) | self.read_bit()
        return value
