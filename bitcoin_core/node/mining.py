"""Block-template construction for mining RPC clients."""

from __future__ import annotations

import heapq
import time
from typing import Any

from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.consensus.pow import decode_compact_target
from bitcoin_core.consensus.subsidy import block_subsidy
from bitcoin_core.consensus.versionbits import (
    VERSIONBITS_TOP_BITS,
    ThresholdState,
    VersionBits,
)
from bitcoin_core.crypto.hashes import hash256
from bitcoin_core.node.chain import BlockIndex, HeaderChain, expected_work_bits
from bitcoin_core.node.mempool import Mempool, MempoolEntry
from bitcoin_core.node.storage import SQLiteNodeStore

MAX_BLOCK_WEIGHT = 4_000_000
MAX_BLOCK_SIGOP_COST = 80_000
WITNESS_COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")


def _template_transactions(mempool: Mempool) -> list[MempoolEntry]:
    """Order transactions parent-first, preferring the best ready fee rate."""
    entries = mempool.entries
    indegree = {txid: sum(parent in entries for parent in entry.parents) for txid, entry in entries.items()}
    children: dict[bytes, set[bytes]] = {txid: set() for txid in entries}
    for txid, entry in entries.items():
        for parent in entry.parents:
            if parent in entries:
                children[parent].add(txid)

    def priority(txid: bytes) -> tuple[int, int, bytes]:
        entry = entries[txid]
        # Compare fee rates exactly, then prefer older transactions for stable results.
        return (-entry.modified_fee * 1_000_000 // max(1, entry.vsize), entry.added_at, txid)

    ready = [(priority(txid), txid) for txid, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    ordered: list[MempoolEntry] = []
    while ready:
        _score, txid = heapq.heappop(ready)
        ordered.append(entries[txid])
        for child in children[txid]:
            indegree[child] -= 1
            if indegree[child] == 0:
                heapq.heappush(ready, (priority(child), child))
    return ordered


def _selected_transactions(
    mempool: Mempool,
    *,
    segwit_active: bool,
) -> tuple[list[MempoolEntry], list[dict[str, Any]], int]:
    ordered = _template_transactions(mempool)
    selected: list[MempoolEntry] = []
    included: set[bytes] = set()
    total_fee = 0
    weight = 4_500  # Reserve room for the header, coinbase, and transaction-count encoding.
    sigop_cost = 0
    position: dict[bytes, int] = {}
    template: list[dict[str, Any]] = []

    for entry in ordered:
        if any(parent in mempool.entries and parent not in included for parent in entry.parents):
            continue
        entry_weight = max(entry.weight, entry.vsize * 4)
        entry_sigops = entry.sigop_cost
        if weight + entry_weight > MAX_BLOCK_WEIGHT or sigop_cost + entry_sigops > MAX_BLOCK_SIGOP_COST:
            continue
        depends = sorted(position[parent] for parent in entry.parents if parent in position)
        template.append(
            {
                "data": entry.transaction.serialize().hex(),
                "txid": entry.txid[::-1].hex(),
                "hash": entry.wtxid[::-1].hex(),
                "depends": depends,
                "fee": entry.fee,
                "sigops": entry_sigops if segwit_active else entry_sigops // 4,
                "weight": entry_weight,
            }
        )
        selected.append(entry)
        included.add(entry.txid)
        position[entry.txid] = len(template)
        total_fee += entry.fee
        weight += entry_weight
        sigop_cost += entry_sigops
    return selected, template, total_fee


def _witness_commitment(entries: list[MempoolEntry]) -> str:
    leaves = [bytes(32), *(entry.wtxid for entry in entries)]
    while len(leaves) > 1:
        if len(leaves) & 1:
            leaves.append(leaves[-1])
        leaves = [hash256(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
    witness_root = leaves[0]
    commitment = hash256(witness_root + bytes(32))
    return (WITNESS_COMMITMENT_PREFIX + commitment).hex()


def create_block_template(
    headers: HeaderChain,
    store: SQLiteNodeStore,
    mempool: Mempool,
    params: ConsensusParams,
    *,
    client_rules: set[str],
) -> dict[str, Any]:
    """Build a BIP22-style template against the current active tip."""
    best_hash = store.best_block()
    previous: BlockIndex | None = headers.indexes.get(best_hash) if best_hash is not None else None
    if previous is None:
        raise ValueError("active chain is unavailable")
    signet_active = bool(params.signet_challenge)
    if signet_active and "signet" not in client_rules:
        raise ValueError("getblocktemplate must be called with the signet rule")

    height = previous.height + 1
    segwit_active = params.segwit_height is not None and height >= params.segwit_height
    if segwit_active and "segwit" not in client_rules:
        raise ValueError("client must include the segwit rule")
    csv_active = params.csv_height is not None and height >= params.csv_height

    _selected, transactions, fees = _selected_transactions(mempool, segwit_active=segwit_active)
    timestamp = max(int(time.time()), previous.median_time_past + 1)
    bits = expected_work_bits(previous, timestamp, params)
    target, negative, overflow = decode_compact_target(bits)
    if negative or overflow or target <= 0:
        raise ValueError("active chain has an invalid proof-of-work target")

    rules: list[str] = []
    if csv_active:
        rules.append("csv")
    if segwit_active:
        rules.extend(("!segwit", "taproot"))
    if signet_active:
        rules.append("!signet")

    version = VERSIONBITS_TOP_BITS
    vbavailable: dict[str, int] = {}
    for name, deployment in params.versionbits_deployments:
        state = VersionBits(deployment).state_for(previous)
        gbt_name = name if deployment.gbt_optional_rule else f"!{name}"
        if state in (ThresholdState.STARTED, ThresholdState.LOCKED_IN):
            vbavailable[gbt_name] = deployment.bit
            version |= deployment.mask
            if state is ThresholdState.LOCKED_IN and not deployment.gbt_optional_rule and name not in client_rules:
                version &= ~deployment.mask
        elif state is ThresholdState.ACTIVE:
            active_rule = gbt_name
            if active_rule.startswith("!") and name not in client_rules:
                raise ValueError(f"client must include the {name} rule")
            if active_rule not in rules:
                rules.append(active_rule)

    result: dict[str, Any] = {
        "capabilities": ["proposal"],
        "version": version,
        "rules": rules,
        "vbavailable": vbavailable,
        "vbrequired": 0,
        "previousblockhash": previous.block_hash[::-1].hex(),
        "transactions": transactions,
        "coinbaseaux": {"flags": ""},
        "coinbasevalue": block_subsidy(height, params) + fees,
        "longpollid": previous.block_hash[::-1].hex() + str(mempool.transactions_updated),
        "target": f"{target:064x}",
        "mintime": previous.median_time_past + 1,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "sigoplimit": MAX_BLOCK_SIGOP_COST if segwit_active else MAX_BLOCK_SIGOP_COST // 4,
        "sizelimit": 4_000_000 if segwit_active else 1_000_000,
        "curtime": timestamp,
        "bits": f"{bits:08x}",
        "height": height,
    }
    if segwit_active:
        result["weightlimit"] = MAX_BLOCK_WEIGHT
        result["default_witness_commitment"] = _witness_commitment(_selected)
    if signet_active:
        result["signet_challenge"] = params.signet_challenge.hex()
    return result
