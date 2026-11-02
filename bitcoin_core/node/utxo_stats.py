"""Streaming statistics and hash commitments for the active UTXO set."""

from __future__ import annotations

import hashlib
import os
from typing import Any

from bitcoin_core.crypto.muhash import MuHash3072
from bitcoin_core.node.storage import SQLiteNodeStore
from bitcoin_core.serialization.compact_size import write_compact_size

SATOSHIS_PER_COIN = 100_000_000


def serialize_utxo_entry(outpoint: tuple[bytes, int], coin) -> bytes:
    """Serialize a coin in the consensus-defined coinstats commitment format."""
    txid, output_index = outpoint
    if len(txid) != 32 or not 0 <= output_index <= 0xFFFFFFFF:
        raise ValueError("invalid UTXO outpoint")
    if not 0 <= coin.height <= 0x7FFFFFFF:
        raise ValueError("UTXO height cannot be encoded")
    if not 0 <= coin.value <= 0x7FFFFFFFFFFFFFFF:
        raise ValueError("UTXO amount cannot be encoded")
    script = coin.script_pubkey
    height_code = (coin.height << 1) | int(coin.coinbase)
    return (
        txid
        + output_index.to_bytes(4, "little")
        + height_code.to_bytes(4, "little")
        + _write_varint(_compress_amount(coin.value))
        + write_compact_size(len(script))
        + script
    )


def _compress_amount(amount: int) -> int:
    """Use Bitcoin Core's CTxOut amount compressor for disk/hash serialization."""
    if amount == 0:
        return 0
    exponent = 0
    while amount % 10 == 0 and exponent < 9:
        amount //= 10
        exponent += 1
    if exponent < 9:
        digit = amount % 10
        return 1 + (amount // 10 * 9 + digit - 1) * 10 + exponent
    return 1 + (amount - 1) * 10 + 9


def _write_varint(value: int) -> bytes:
    """Serialize an unsigned integer using Bitcoin's subtract-one VARINT."""
    if value < 0:
        raise ValueError("VARINT value cannot be negative")
    encoded = bytearray()
    while True:
        encoded.append((value & 0x7F) | (0x80 if encoded else 0))
        if value <= 0x7F:
            break
        value = (value >> 7) - 1
    encoded.reverse()
    return bytes(encoded)


def calculate_utxo_stats(store: SQLiteNodeStore, block_hash: bytes, height: int, hash_type: str) -> dict[str, Any]:
    """Compute Core-compatible UTXO counts, totals, and the selected commitment."""
    if hash_type not in {"hash_serialized_3", "muhash", "none"}:
        raise ValueError("unknown UTXO hash type")
    output_count, transaction_count, total_amount = store.utxo_summary()
    bogosize = 0
    legacy_digest = hashlib.sha256() if hash_type == "hash_serialized_3" else None
    muhash = MuHash3072() if hash_type == "muhash" else None
    for outpoint, coin in store.iter_coins():
        bogosize += 32 + 4 + 4 + 8 + 2 + len(coin.script_pubkey)
        if legacy_digest is not None:
            legacy_digest.update(serialize_utxo_entry(outpoint, coin))
        if muhash is not None:
            muhash.insert(serialize_utxo_entry(outpoint, coin))

    result: dict[str, Any] = {
        "height": height,
        "bestblock": block_hash[::-1].hex(),
        "txouts": output_count,
        "bogosize": bogosize,
        "transactions": transaction_count,
        "disk_size": os.path.getsize(store.path) if os.path.exists(store.path) else 0,
        "total_amount": total_amount / SATOSHIS_PER_COIN,
    }
    if legacy_digest is not None:
        result["hash_serialized_3"] = hash256_finish(legacy_digest)[::-1].hex()
    elif muhash is not None:
        result["muhash"] = muhash.finalize()[::-1].hex()
    return result


def hash256_finish(first_sha256) -> bytes:
    """Finish the streaming SHA256d used by hash_serialized_3."""
    return hashlib.sha256(first_sha256.digest()).digest()
