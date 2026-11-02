"""BIP 157 compact-filter request and response payload codecs."""

from __future__ import annotations

from io import BytesIO

from bitcoin_core.serialization.compact_size import read_compact_size, write_compact_size

BASIC_FILTER_TYPE = 0
MAX_GETCFILTERS = 1_000
MAX_GETCFHEADERS = 2_000
CF_CHECKPT_INTERVAL = 1_000


def decode_filter_range(payload: bytes) -> tuple[int, int, bytes]:
    """Decode getcfilters/getcfheaders payloads."""
    if len(payload) != 37:
        raise ValueError("compact-filter range request must contain 37 bytes")
    return payload[0], int.from_bytes(payload[1:5], "little"), payload[5:]


def decode_filter_checkpoints(payload: bytes) -> tuple[int, bytes]:
    """Decode a getcfcheckpt payload."""
    if len(payload) != 33:
        raise ValueError("getcfcheckpt request must contain 33 bytes")
    return payload[0], payload[1:]


def encode_cfilter(filter_type: int, block_hash: bytes, encoded_filter: bytes) -> bytes:
    if len(block_hash) != 32:
        raise ValueError("block hash must contain 32 bytes")
    return bytes((filter_type,)) + block_hash + write_compact_size(len(encoded_filter)) + encoded_filter


def encode_cfheaders(
    filter_type: int,
    stop_hash: bytes,
    previous_header: bytes,
    filter_hashes: tuple[bytes, ...] | list[bytes],
) -> bytes:
    if len(stop_hash) != 32 or len(previous_header) != 32 or any(len(item) != 32 for item in filter_hashes):
        raise ValueError("compact-filter hashes and headers must contain 32 bytes")
    return (
        bytes((filter_type,))
        + stop_hash
        + previous_header
        + write_compact_size(len(filter_hashes))
        + b"".join(filter_hashes)
    )


def encode_cfcheckpt(filter_type: int, stop_hash: bytes, headers: tuple[bytes, ...] | list[bytes]) -> bytes:
    if len(stop_hash) != 32 or any(len(item) != 32 for item in headers):
        raise ValueError("compact-filter checkpoint hashes must contain 32 bytes")
    return bytes((filter_type,)) + stop_hash + write_compact_size(len(headers)) + b"".join(headers)


def decode_cfheaders(payload: bytes) -> tuple[int, bytes, bytes, tuple[bytes, ...]]:
    """Decode a cfheaders payload and reject trailing or truncated values."""
    if len(payload) < 65:
        raise ValueError("truncated cfheaders payload")
    stream = BytesIO(payload[65:])
    count = read_compact_size(stream)
    if count > MAX_GETCFHEADERS:
        raise ValueError("cfheaders payload contains too many hashes")
    hashes = stream.read(count * 32)
    if len(hashes) != count * 32 or stream.read(1):
        raise ValueError("malformed cfheaders payload")
    return payload[0], payload[1:33], payload[33:65], tuple(
        hashes[offset : offset + 32] for offset in range(0, len(hashes), 32)
    )
