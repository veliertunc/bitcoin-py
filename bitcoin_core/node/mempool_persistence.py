"""Bitcoin Core-compatible persistence for accepted mempool transactions."""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from bitcoin_core.consensus.chainstate import CoinsView, InputVerifier
from bitcoin_core.crypto.hashes import hash256
from bitcoin_core.node.mempool import Mempool, MempoolError
from bitcoin_core.primitives.block import _read_transaction
from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.serialization.compact_size import read_compact_size, write_compact_size

LEGACY_PYTHON_MAGIC = b"BTCMPY01"
LEGACY_PYTHON_VERSION = 1
CORE_DUMP_VERSION_NO_XOR = 1
CORE_DUMP_VERSION = 2
MAX_MEMPOOL_FILE_BYTES = 512 * 1024 * 1024
MAX_SAVED_TRANSACTIONS = 1_000_000


@dataclass(frozen=True, slots=True)
class MempoolLoadResult:
    """Summary of a mempool restore attempt."""

    loaded: int = 0
    expired: int = 0
    rejected: int = 0
    already_there: int = 0
    reason: str | None = None


def dump_mempool(path: str | Path, magic: bytes, mempool: Mempool) -> int:
    """Write Core's version-2 mempool.dat format using a fresh XOR key."""
    if len(magic) != 4:
        raise ValueError("network magic must contain four bytes")
    entries = tuple(mempool.entries.values())
    if len(entries) > MAX_SAVED_TRANSACTIONS:
        raise ValueError("mempool transaction count exceeds the persistence limit")

    key = secrets.token_bytes(8)
    if not any(key):
        key = b"\x01" + key[1:]
    plain_tail = bytearray(len(entries).to_bytes(8, "little"))
    stored_ids: set[bytes] = set()
    for entry in entries:
        plain_tail.extend(entry.transaction.serialize(include_witness=True))
        plain_tail.extend(entry.added_at.to_bytes(8, "little", signed=True))
        plain_tail.extend(entry.fee_delta.to_bytes(8, "little", signed=True))
        stored_ids.add(entry.txid)
    leftover_deltas = {
        txid: delta for txid, delta in mempool.fee_deltas.items() if txid not in stored_ids
    }
    plain_tail.extend(write_compact_size(len(leftover_deltas)))
    for txid in sorted(leftover_deltas, key=lambda item: int.from_bytes(item, "little")):
        plain_tail.extend(txid)
        plain_tail.extend(leftover_deltas[txid].to_bytes(8, "little", signed=True))
    unbroadcast = sorted(
        (txid for txid in mempool.unbroadcast_txs if txid in mempool.entries),
        key=lambda txid: int.from_bytes(txid, "little"),
    )
    plain_tail.extend(write_compact_size(len(unbroadcast)))
    plain_tail.extend(b"".join(unbroadcast))

    # Core's AutoFile applies the repeating key at each absolute file offset.
    offset = 8 + len(write_compact_size(len(key))) + len(key)
    obfuscated = _xor_obfuscation(plain_tail, key, offset)
    payload = (
        CORE_DUMP_VERSION.to_bytes(8, "little")
        + write_compact_size(len(key))
        + key
        + obfuscated
    )
    if len(payload) > MAX_MEMPOOL_FILE_BYTES:
        raise ValueError("mempool snapshot exceeds the persistence size limit")

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".new")
    try:
        with temporary.open("wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return len(payload)


def load_mempool(
    path: str | Path,
    magic: bytes,
    mempool: Mempool,
    coins: CoinsView,
    height: int,
    *,
    median_time_past: int,
    input_verifier: InputVerifier,
    now: int | None = None,
    expiry_seconds: int = 14 * 24 * 60 * 60,
    use_current_time: bool = False,
    apply_unbroadcast_set: bool = True,
    apply_fee_delta_priority: bool = False,
    missing_ok: bool = True,
) -> MempoolLoadResult:
    """Load Core v1/v2 or prior Python snapshots and revalidate every entry."""
    source = Path(path)
    if not source.exists():
        return MempoolLoadResult() if missing_ok else MempoolLoadResult(reason="mempool file does not exist")
    try:
        if source.stat().st_size > MAX_MEMPOOL_FILE_BYTES:
            raise ValueError("mempool file exceeds the configured size limit")
        raw = source.read_bytes()
        if len(raw) > MAX_MEMPOOL_FILE_BYTES:
            raise ValueError("mempool file exceeds the configured size limit")
        if raw.startswith(LEGACY_PYTHON_MAGIC):
            transactions, fee_deltas, unbroadcast = _read_legacy_python_dump(raw, magic)
        else:
            transactions, fee_deltas, unbroadcast = _read_core_dump(raw)
    except (OSError, EOFError, ValueError) as exc:
        return MempoolLoadResult(reason=str(exc))

    timestamp = int(time.time()) if now is None else now
    loaded = expired = rejected = already_there = 0
    accepted_ids: set[bytes] = set()
    listed_ids = {transaction.txid for transaction, _saved_time in transactions}
    for transaction, saved_time in transactions:
        if apply_fee_delta_priority:
            fee_delta = fee_deltas.get(transaction.txid, 0)
            if fee_delta:
                mempool.prioritise(transaction.txid, fee_delta)
        added_at = timestamp if use_current_time else saved_time
        if added_at > timestamp + 60 or timestamp - added_at > expiry_seconds:
            expired += 1
            continue
        if transaction.txid in mempool.entries:
            already_there += 1
            continue
        try:
            entry = mempool.accept(
                transaction,
                coins,
                height,
                input_verifier=input_verifier,
                median_time_past=median_time_past,
                now=added_at,
            )
        except (MempoolError, ValueError):
            rejected += 1
            continue
        loaded += 1
        accepted_ids.add(entry.txid)
    if apply_fee_delta_priority:
        for txid, fee_delta in fee_deltas.items():
            if txid not in listed_ids and fee_delta:
                mempool.prioritise(txid, fee_delta)
    if apply_unbroadcast_set:
        mempool.unbroadcast_txs.update(accepted_ids & unbroadcast)
    return MempoolLoadResult(loaded, expired, rejected, already_there)


def _read_core_dump(raw: bytes) -> tuple[list[tuple[Transaction, int]], dict[bytes, int], set[bytes]]:
    """Decode Bitcoin Core's native version-1 or obfuscated version-2 dump."""
    if len(raw) < 8:
        raise ValueError("mempool file is truncated")
    version = int.from_bytes(raw[:8], "little")
    cursor = 8
    if version == CORE_DUMP_VERSION:
        key_stream = BytesIO(raw[cursor:])
        key_length = read_compact_size(key_stream)
        cursor += key_stream.tell()
        if key_length != 8 or cursor + key_length > len(raw):
            raise ValueError("invalid mempool obfuscation key")
        key = raw[cursor : cursor + key_length]
        cursor += key_length
        tail = _xor_obfuscation(raw[cursor:], key, cursor)
    elif version == CORE_DUMP_VERSION_NO_XOR:
        tail = raw[cursor:]
    else:
        raise ValueError("unsupported Core mempool file version")

    stream = BytesIO(tail)
    count = int.from_bytes(_read_exact(stream, 8), "little")
    if count > MAX_SAVED_TRANSACTIONS:
        raise ValueError("mempool transaction count exceeds the configured limit")
    transactions: list[tuple[Transaction, int]] = []
    fee_deltas: dict[bytes, int] = {}
    for _ in range(count):
        transaction = _read_transaction(stream)
        saved_time = int.from_bytes(_read_exact(stream, 8), "little", signed=True)
        fee_delta = int.from_bytes(_read_exact(stream, 8), "little", signed=True)
        transactions.append((transaction, saved_time))
        if fee_delta:
            fee_deltas[transaction.txid] = fee_delta

    delta_count = read_compact_size(stream)
    if delta_count > MAX_SAVED_TRANSACTIONS:
        raise ValueError("mempool fee delta count exceeds the configured limit")
    for _ in range(delta_count):
        txid = _read_exact(stream, 32)
        delta = int.from_bytes(_read_exact(stream, 8), "little", signed=True)
        if delta:
            combined = fee_deltas.get(txid, 0) + delta
            fee_deltas[txid] = max(-(1 << 63), min((1 << 63) - 1, combined))

    unbroadcast_count = read_compact_size(stream)
    if unbroadcast_count > MAX_SAVED_TRANSACTIONS:
        raise ValueError("mempool unbroadcast count exceeds the configured limit")
    unbroadcast = {_read_exact(stream, 32) for _ in range(unbroadcast_count)}
    if stream.read(1):
        raise ValueError("trailing data in mempool file")
    return transactions, fee_deltas, unbroadcast


def _read_legacy_python_dump(
    raw: bytes,
    network_magic: bytes,
) -> tuple[list[tuple[Transaction, int]], dict[bytes, int], set[bytes]]:
    """Read the checksummed private format emitted by earlier Python stages."""
    minimum = len(LEGACY_PYTHON_MAGIC) + 4 + 4 + 8 + 1 + 32
    if len(raw) < minimum:
        raise ValueError("mempool file is truncated")
    body, checksum = raw[:-32], raw[-32:]
    if hash256(body) != checksum:
        raise ValueError("mempool file checksum mismatch")
    stream = BytesIO(body)
    if _read_exact(stream, len(LEGACY_PYTHON_MAGIC)) != LEGACY_PYTHON_MAGIC:
        raise ValueError("unsupported mempool file format")
    if int.from_bytes(_read_exact(stream, 4), "little") != LEGACY_PYTHON_VERSION:
        raise ValueError("unsupported mempool file version")
    if _read_exact(stream, 4) != network_magic:
        raise ValueError("mempool file belongs to a different network")
    count = int.from_bytes(_read_exact(stream, 8), "little")
    if count > MAX_SAVED_TRANSACTIONS:
        raise ValueError("mempool transaction count exceeds the configured limit")
    transactions = []
    for _ in range(count):
        size = read_compact_size(stream)
        if size > 4_000_000:
            raise ValueError("saved transaction exceeds the size limit")
        transactions.append(
            (
                Transaction.deserialize(_read_exact(stream, size)),
                int.from_bytes(_read_exact(stream, 8), "little", signed=True),
            )
        )
    unbroadcast_count = read_compact_size(stream)
    if unbroadcast_count > count:
        raise ValueError("mempool unbroadcast count exceeds transaction count")
    unbroadcast = {_read_exact(stream, 32) for _ in range(unbroadcast_count)}
    if stream.read(1):
        raise ValueError("trailing data in mempool file")
    return transactions, {}, unbroadcast


def _xor_obfuscation(data: bytes | bytearray, key: bytes, file_offset: int) -> bytes:
    """Apply Core's position-aligned repeating uint64 XOR obfuscation."""
    if len(key) != 8:
        raise ValueError("mempool obfuscation key must contain eight bytes")
    return bytes(value ^ key[(file_offset + index) % 8] for index, value in enumerate(data))


def _read_exact(stream: BytesIO, length: int) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise EOFError("truncated mempool file")
    return data
