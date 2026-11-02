"""Authenticated JSON-RPC methods and a small asynchronous HTTP server."""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bitcoin_core.consensus.chainstate import CoinsView
from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.consensus.pow import decode_compact_target
from bitcoin_core.consensus.subsidy import block_subsidy
from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.node.chain import HeaderChain
from bitcoin_core.node.mempool import Mempool, MempoolEntry, MempoolError
from bitcoin_core.node.mempool_persistence import MempoolLoadResult
from bitcoin_core.node.mining import create_block_template
from bitcoin_core.node.relay import MempoolRelay
from bitcoin_core.node.storage import SQLiteNodeStore
from bitcoin_core.node.utxo_stats import calculate_utxo_stats
from bitcoin_core.primitives.block import Block, BlockHeader
from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.serialization.compact_size import write_compact_size

MAX_RPC_BODY = 16 * 1024 * 1024
MAX_HTTP_HEADER = 64 * 1024


def _truncated_median(values: list[int]) -> int:
    """Return Core's median, truncating the mean of the two middle values."""
    if not values:
        return 0
    middle = len(values) // 2
    if len(values) % 2:
        return values[middle]
    return (values[middle - 1] + values[middle]) // 2


class RPCError(ValueError):
    """JSON-RPC error with the standard numeric code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass(slots=True)
class NodeRPC:
    """Expose a focused set of chain, UTXO, and mempool JSON-RPC methods."""

    store: SQLiteNodeStore
    headers: HeaderChain
    coins: CoinsView
    params: ConsensusParams
    mempool: Mempool
    relay: MempoolRelay | None = None
    network_name: str = "main"
    peers: Callable[[], list[PeerConnection]] = field(default=lambda: [])
    submit_block: Callable[[Block], Awaitable[str | None]] | None = None
    proposal_check: Callable[[Block], str | None] | None = None
    save_mempool: Callable[[], str] | None = None
    import_mempool: Callable[[str, dict[str, bool]], MempoolLoadResult] | None = None

    async def call(self, method: str, params: list[Any] | dict[str, Any] | None = None) -> Any:
        params = [] if params is None else params
        if method == "getblockcount":
            return self.store.best_height()
        if method == "getdifficulty":
            return self._active_difficulty()
        if method == "getchaintips":
            return self._chain_tips()
        if method == "getchaintxstats":
            return self._chain_tx_stats(
                self._param(params, 0, "nblocks"),
                self._param(params, 1, "blockhash"),
            )
        if method == "getblockstats":
            return self._block_stats(
                self._param(params, 0, "hash_or_height"),
                self._param(params, 1, "stats"),
            )
        if method == "gettxoutsetinfo":
            return self._get_txout_set_info(
                self._param(params, 0, "hash_type", "hash_serialized_3"),
                self._param(params, 1, "hash_or_height"),
                self._param(params, 2, "use_index", True),
            )
        if method == "getbestblockhash":
            block_hash = self.store.best_block()
            if block_hash is None:
                raise RPCError(-8, "No active block is available")
            return block_hash[::-1].hex()
        if method == "getblockhash":
            height = self._param(params, 0, "height")
            if not isinstance(height, int) or height < 0:
                raise RPCError(-8, "Block height must be a non-negative integer")
            block_hash = self.store.active_block_hash(height)
            if block_hash is None:
                raise RPCError(-8, "Block height is outside the active chain")
            return block_hash[::-1].hex()
        if method == "getblockheader":
            return self._get_block_header(
                self._param(params, 0, "blockhash"),
                bool(self._param(params, 1, "verbose", True)),
            )
        if method == "getblockfilter":
            return self._get_block_filter(
                self._param(params, 0, "blockhash"),
                self._param(params, 1, "filtertype", "basic"),
            )
        if method == "getblocktemplate":
            request = self._param(params, 0, "template_request", {})
            if not isinstance(request, dict):
                raise RPCError(-8, "template_request must be an object")
            mode = request.get("mode", "template")
            if mode == "proposal":
                if self.proposal_check is None:
                    raise RPCError(-32603, "Block proposal checks are not configured")
                raw_hex = request.get("data")
                if not isinstance(raw_hex, str):
                    raise RPCError(-3, "Missing data String key for proposal")
                try:
                    proposal = Block.deserialize(bytes.fromhex(raw_hex))
                except (EOFError, ValueError) as exc:
                    raise RPCError(-22, "Block decode failed") from exc
                return self.proposal_check(proposal)
            if mode != "template":
                raise RPCError(-8, "only template mode is supported")
            requested_rules = request.get("rules", [])
            if not isinstance(requested_rules, list) or any(not isinstance(rule, str) for rule in requested_rules):
                raise RPCError(-8, "rules must be an array of strings")
            try:
                return create_block_template(
                    self.headers,
                    self.store,
                    self.mempool,
                    self.params,
                    client_rules=set(requested_rules),
                )
            except ValueError as exc:
                raise RPCError(-8, str(exc)) from exc
        if method == "getblock":
            return self._get_block(
                self._param(params, 0, "blockhash"),
                self._param(params, 1, "verbosity", 1),
            )
        if method == "getblockchaininfo":
            return self._blockchain_info()
        if method == "gettxout":
            return self._get_txout(
                self._param(params, 0, "txid"),
                self._param(params, 1, "n"),
                bool(self._param(params, 2, "include_mempool", True)),
            )
        if method == "getrawtransaction":
            return self._get_raw_transaction(
                self._param(params, 0, "txid"),
                self._param(params, 1, "verbosity", self._param(params, 1, "verbose", False)),
                self._param(params, 2, "blockhash"),
            )
        if method == "getrawmempool":
            verbose = bool(self._param(params, 0, "verbose", False))
            include_sequence = bool(self._param(params, 1, "mempool_sequence", False))
            if verbose and include_sequence:
                raise RPCError(-8, "Verbose results cannot contain mempool sequence values")
            if not verbose:
                txids = [entry.txid[::-1].hex() for entry in self.mempool.entries.values()]
                return {"txids": txids, "mempool_sequence": self.mempool.sequence} if include_sequence else txids
            return {
                entry.txid[::-1].hex(): self._mempool_entry_json(entry)
                for entry in self.mempool.entries.values()
            }
        if method == "getmempoolinfo":
            return {
                "loaded": True,
                "size": len(self.mempool.entries),
                "bytes": self.mempool.total_vbytes,
                "usage": self.mempool.total_vbytes,
                "total_fee": sum(entry.fee for entry in self.mempool.entries.values()) / 100_000_000,
                "maxmempool": self.mempool.max_vbytes,
                "mempoolminfee": self.mempool.min_relay_fee_per_kvb / 100_000_000,
                "minrelaytxfee": self.mempool.min_relay_fee_per_kvb / 100_000_000,
                "incrementalrelayfee": self.mempool.min_relay_fee_per_kvb / 100_000_000,
                "unbroadcastcount": len(self.mempool.unbroadcast_txs),
                "mempool_sequence": self.mempool.sequence,
                "permitbaremultisig": self.mempool.permit_bare_multisig,
                "maxdatacarriersize": self.mempool.max_datacarrier_bytes,
            }
        if method == "savemempool":
            if self.save_mempool is None:
                raise RPCError(-32603, "Mempool persistence is not configured")
            try:
                filename = self.save_mempool()
            except (OSError, ValueError) as exc:
                raise RPCError(-32603, f"Unable to persist mempool: {exc}") from exc
            return {"filename": filename}
        if method == "importmempool":
            if self.import_mempool is None:
                raise RPCError(-32603, "Mempool import is not configured")
            filename = self._param(params, 0, "filepath")
            if not isinstance(filename, str):
                raise RPCError(-3, "filepath must be a string")
            options = self._param(params, 1, "options", {})
            if not isinstance(options, dict):
                raise RPCError(-8, "options must be an object")
            normalized: dict[str, bool] = {}
            for key, default in (
                ("use_current_time", True),
                ("apply_fee_delta_priority", False),
                ("apply_unbroadcast_set", False),
            ):
                value = options.get(key, default)
                if not isinstance(value, bool):
                    raise RPCError(-8, f"{key} must be a boolean")
                normalized[key] = value
            result = self.import_mempool(filename, normalized)
            if result.reason is not None:
                raise RPCError(-1, f"Unable to import mempool file: {result.reason}")
            return {}
        if method == "getmempoolentry":
            txid = self._parse_hash(self._param(params, 0, "txid"))
            entry = self.mempool.entries.get(txid)
            if entry is None:
                raise RPCError(-5, "Transaction not in mempool")
            return self._mempool_entry_json(entry)
        if method == "prioritisetransaction":
            txid = self._parse_hash(self._param(params, 0, "txid"))
            if isinstance(params, dict):
                dummy = params.get("dummy")
                fee_delta = params.get("fee_delta")
            else:
                dummy = self._param(params, 1, "dummy")
                fee_delta = self._param(params, 2, "fee_delta")
            if dummy is not None and (
                isinstance(dummy, bool) or not isinstance(dummy, (int, float)) or dummy != 0
            ):
                raise RPCError(-8, "dummy argument must be zero or null")
            if isinstance(fee_delta, bool) or not isinstance(fee_delta, int):
                raise RPCError(-3, "fee_delta must be an integer number of satoshis")
            try:
                self.mempool.prioritise(txid, fee_delta)
            except ValueError as exc:
                raise RPCError(-8, str(exc)) from exc
            return True
        if method == "getprioritisedtransactions":
            result = {}
            for txid, fee_delta in self.mempool.fee_deltas.items():
                entry = self.mempool.entries.get(txid)
                item = {
                    "fee_delta": fee_delta,
                    "in_mempool": entry is not None,
                }
                if entry is not None:
                    item["modified_fee"] = entry.modified_fee
                result[txid[::-1].hex()] = item
            return result
        if method == "gettxspendingprevout":
            return self._get_tx_spending_prevout(
                self._param(params, 0, "outputs"),
                self._param(params, 1, "options", {}),
            )
        if method == "sendrawtransaction":
            if self.relay is None:
                raise RPCError(-32603, "Transaction relay is not configured")
            raw_hex = self._param(params, 0, "hexstring")
            if not isinstance(raw_hex, str):
                raise RPCError(-3, "Transaction data must be hexadecimal text")
            try:
                tx = Transaction.deserialize(bytes.fromhex(raw_hex))
            except (EOFError, ValueError) as exc:
                raise RPCError(-22, "TX decode failed") from exc
            try:
                entry = await self.relay.submit(tx, self.peers(), unbroadcast=True)
            except MempoolError as exc:
                raise RPCError(-26, str(exc)) from exc
            return entry.txid[::-1].hex()
        if method == "submitblock":
            if self.submit_block is None:
                raise RPCError(-32603, "Block submission is not configured")
            raw_hex = self._param(params, 0, "hexdata")
            if not isinstance(raw_hex, str):
                raise RPCError(-8, "Block data must be hexadecimal text")
            try:
                block = Block.deserialize(bytes.fromhex(raw_hex))
            except (EOFError, ValueError) as exc:
                raise RPCError(-22, "Block decode failed") from exc
            return await self.submit_block(block)
        if method == "getnetworkinfo":
            return {
                "version": 1,
                "subversion": "/bitcoin-py:0.1/",
                "protocolversion": 70_016,
                "networkactive": True,
                "connections": sum(peer.established for peer in self.peers()),
                "connections_in": sum(peer.established and peer.inbound for peer in self.peers()),
                "connections_out": sum(peer.established and not peer.inbound for peer in self.peers()),
                "relayfee": self.mempool.min_relay_fee_per_kvb / 100_000_000,
            }
        if method == "getconnectioncount":
            return sum(peer.established for peer in self.peers())
        if method == "getpeerinfo":
            return [self._peer_info(peer, peer_id) for peer_id, peer in enumerate(self.peers())]
        raise RPCError(-32601, f"Method not found: {method}")

    @staticmethod
    def _param(params: list[Any] | dict[str, Any], index: int, name: str, default: Any = None) -> Any:
        if isinstance(params, dict):
            return params.get(name, default)
        if isinstance(params, list):
            return params[index] if index < len(params) else default
        raise RPCError(-32602, "RPC params must be an array or object")

    @staticmethod
    def _parse_hash(value: Any) -> bytes:
        if not isinstance(value, str):
            raise RPCError(-8, "Hash must be hexadecimal text")
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise RPCError(-8, "Hash must be hexadecimal text") from exc
        if len(decoded) != 32:
            raise RPCError(-8, "Hash must contain 32 bytes")
        return decoded[::-1]

    def _get_block_header(self, block_hash_value: Any, verbose: bool) -> Any:
        block_hash = self._parse_hash(block_hash_value)
        raw_header = self.store.load_header(block_hash)
        if raw_header is None:
            raise RPCError(-5, "Block header not found")
        if not verbose:
            return raw_header.hex()
        header = BlockHeader.deserialize(raw_header)
        index = self.headers.indexes.get(block_hash)
        target, negative, overflow = decode_compact_target(header.bits)
        if negative or overflow or target <= 0:
            difficulty = 0.0
        else:
            difficulty = self.params.pow_limit / target
        result = {
            "hash": block_hash[::-1].hex(),
            "confirmations": self.store.best_height() - index.height + 1
            if index and self.store.active_block_hash(index.height) == block_hash else -1,
            "height": index.height if index else self.store.header_height(block_hash),
            "version": header.version,
            "versionHex": f"{header.version & 0xFFFFFFFF:08x}",
            "merkleroot": header.merkle_root[::-1].hex(),
            "time": header.timestamp,
            "mediantime": index.median_time_past if index else header.timestamp,
            "nonce": header.nonce,
            "bits": f"{header.bits:08x}",
            "difficulty": difficulty,
            "chainwork": f"{index.chainwork:064x}" if index else "0" * 64,
        }
        if header.previous_block != bytes(32):
            result["previousblockhash"] = header.previous_block[::-1].hex()
        return result

    @staticmethod
    def _transaction_json(tx: Transaction) -> dict[str, Any]:
        raw = tx.serialize(include_witness=True)
        stripped = tx.serialize(include_witness=False)
        return {
            "txid": tx.txid_hex,
            "hash": tx.wtxid_hex,
            "version": tx.version,
            "size": len(raw),
            "vsize": (len(stripped) * 3 + len(raw) + 3) // 4,
            "weight": len(stripped) * 3 + len(raw),
            "locktime": tx.lock_time,
            "vin": [
                ({"coinbase": txin.script_sig.hex(), "sequence": txin.sequence}
                 if txin.previous_output.is_null else {
                     "txid": txin.previous_output.txid[::-1].hex(),
                     "vout": txin.previous_output.index,
                     "scriptSig": {"asm": "", "hex": txin.script_sig.hex()},
                     "txinwitness": [item.hex() for item in txin.witness] if txin.witness else [],
                     "sequence": txin.sequence,
                 })
                for txin in tx.inputs
            ],
            "vout": [
                {
                    "value": output.value / 100_000_000,
                    "n": index,
                    "scriptPubKey": {"asm": "", "hex": output.script_pubkey.hex(), "type": "nonstandard"},
                }
                for index, output in enumerate(tx.outputs)
            ],
        }

    def _get_raw_transaction(self, txid_value: Any, verbosity: Any, blockhash_value: Any = None) -> Any:
        if not isinstance(verbosity, (bool, int)) or verbosity not in (0, 1, 2, False, True):
            raise RPCError(-8, "Transaction verbosity must be 0, 1, or 2")
        txid = self._parse_hash(txid_value)
        requested_block = self._parse_hash(blockhash_value) if blockhash_value is not None else None
        tx = self.mempool.get(txid) if requested_block is None else None
        block_hash = None
        height = None
        if tx is None:
            indexed = self.store.find_transaction(txid)
            if indexed is None or (requested_block is not None and indexed[0] != requested_block):
                raise RPCError(-5, "Transaction not found in mempool or specified block")
            block_hash, height, _position, tx = indexed
        raw = tx.serialize(include_witness=True)
        if verbosity is False or verbosity == 0:
            return raw.hex()
        result = self._transaction_json(tx)
        result["hex"] = raw.hex()
        if verbosity == 2:
            result["vin"] = [
                {**item, "prevout": self._prevout_json(txin.previous_output.txid, txin.previous_output.index)}
                if not txin.previous_output.is_null else item
                for item, txin in zip(result["vin"], tx.inputs)
            ]
        if block_hash is not None and height is not None:
            result["blockhash"] = block_hash[::-1].hex()
            result["confirmations"] = self.store.best_height() - height + 1
        return result

    def _prevout_json(self, txid: bytes, output_index: int) -> dict[str, Any] | None:
        block_coin = self.coins.coins.get((txid, output_index))
        parent = self.mempool.get(txid)
        if block_coin is not None:
            return {"value": block_coin.value / 100_000_000,
                    "scriptPubKey": {"asm": "", "hex": block_coin.script_pubkey.hex(), "type": "nonstandard"}}
        if parent is not None and output_index < len(parent.outputs):
            output = parent.outputs[output_index]
            return {"value": output.value / 100_000_000,
                    "scriptPubKey": {"asm": "", "hex": output.script_pubkey.hex(), "type": "nonstandard"}}
        return None

    def _get_block(self, block_hash_value: Any, verbosity: Any) -> Any:
        block_hash = self._parse_hash(block_hash_value)
        block = self.store.load_block(block_hash)
        if block is None:
            raise RPCError(-5, "Block not found")
        if not isinstance(verbosity, (bool, int)) or verbosity not in (0, 1, 2, False, True):
            raise RPCError(-8, "Block verbosity must be 0, 1, or 2")
        if verbosity is False or verbosity == 0:
            return block.serialize().hex()
        index = self.headers.indexes.get(block_hash)
        stripped_size = 80 + len(write_compact_size(len(block.transactions))) + sum(
            len(tx.serialize(include_witness=False)) for tx in block.transactions
        )
        total_size = len(block.serialize())
        result = {
            "hash": block_hash[::-1].hex(),
            "confirmations": self.store.best_height() - index.height + 1
            if index and self.store.active_block_hash(index.height) == block_hash else -1,
            "size": total_size,
            "strippedsize": stripped_size,
            "weight": stripped_size * 3 + total_size,
            "height": index.height if index else self.store.header_height(block_hash),
            "version": block.header.version,
            "versionHex": f"{block.header.version & 0xFFFFFFFF:08x}",
            "merkleroot": block.header.merkle_root[::-1].hex(),
            "tx": [tx.txid_hex for tx in block.transactions],
            "time": block.header.timestamp,
            "nonce": block.header.nonce,
            "bits": f"{block.header.bits:08x}",
            "chainwork": f"{index.chainwork:064x}" if index else "0" * 64,
        }
        if block.header.previous_block != bytes(32):
            result["previousblockhash"] = block.header.previous_block[::-1].hex()
        if verbosity == 2:
            result["tx"] = [self._transaction_json(tx) for tx in block.transactions]
        return result

    def _get_block_filter(self, block_hash_value: Any, filter_type: Any) -> dict[str, str]:
        if filter_type != "basic":
            raise RPCError(-5, "Unknown filtertype")
        block_hash = self._parse_hash(block_hash_value)
        filter_data = self.store.load_basic_filter(block_hash)
        if filter_data is None:
            raise RPCError(-5, "Filter not found. Block is not connected or filter data is unavailable.")
        encoded_filter, filter_header = filter_data
        return {"filter": encoded_filter.hex(), "header": filter_header[::-1].hex()}

    def _get_txout_set_info(
        self,
        hash_type: Any,
        hash_or_height: Any = None,
        use_index: Any = True,
    ) -> dict[str, Any]:
        if hash_or_height is not None:
            raise RPCError(-8, "Querying specific block heights requires coinstatsindex")
        if not isinstance(hash_type, str) or hash_type not in ("hash_serialized_3", "muhash", "none"):
            raise RPCError(-8, f"'{hash_type}' is not a valid hash_type")
        if not isinstance(use_index, bool):
            raise RPCError(-8, "use_index must be a boolean")
        best_hash = self.store.best_block()
        if best_hash is None:
            raise RPCError(-32603, "Active chain is unavailable")
        try:
            return calculate_utxo_stats(self.store, best_hash, self.store.best_height(), hash_type)
        except (OSError, ValueError) as exc:
            raise RPCError(-32603, f"Unable to compute UTXO statistics: {exc}") from exc

    def _blockchain_info(self) -> dict[str, Any]:
        best = self.store.best_block()
        tip = self.headers.indexes.get(best) if best is not None else None
        header_tip = self.headers.tip
        return {
            "chain": self.network_name,
            "blocks": self.store.best_height(),
            "headers": header_tip.height if header_tip else -1,
            "bestblockhash": best[::-1].hex() if best else "0" * 64,
            "difficulty": self._active_difficulty(),
            "chainwork": f"{tip.chainwork:064x}" if tip else "0" * 64,
            "pruned": False,
        }

    def _active_difficulty(self) -> float:
        block_hash = self.store.best_block()
        if block_hash is None:
            return 0.0
        raw_header = self.store.load_header(block_hash)
        if raw_header is None:
            return 0.0
        bits = BlockHeader.deserialize(raw_header).bits
        target, negative, overflow = decode_compact_target(bits)
        return 0.0 if negative or overflow or not target else self.params.pow_limit / target

    def _chain_tx_stats(self, window_blocks: Any, block_hash_value: Any) -> dict[str, Any]:
        """Compute Core-compatible cumulative and windowed active-chain tx statistics."""
        tip_hash = self.store.best_block()
        tip = self.headers.indexes.get(tip_hash) if tip_hash is not None else None
        if block_hash_value is not None:
            requested_hash = self._parse_hash(block_hash_value)
            tip = self.headers.indexes.get(requested_hash)
            if tip is None:
                raise RPCError(-5, "Block not found")
            if self.store.active_block_hash(tip.height) != requested_hash:
                raise RPCError(-8, "Block is not in main chain")
        if tip is None:
            raise RPCError(-32603, "Active chain is unavailable")

        default_window = 30 * 24 * 60 * 60 // self.params.target_spacing
        if window_blocks is None:
            count = max(0, min(default_window, tip.height - 1))
        else:
            if isinstance(window_blocks, bool) or not isinstance(window_blocks, int):
                raise RPCError(-8, "Block count must be an integer")
            count = window_blocks
            if count < 0 or (count > 0 and count >= tip.height):
                raise RPCError(
                    -8,
                    "Invalid block count: should be between 0 and the block's height - 1",
                )
        past = tip.ancestor(tip.height - count)
        if past is None:
            raise RPCError(-32603, "Window start block is unavailable")

        result: dict[str, Any] = {
            "time": tip.header.timestamp,
            "txcount": self.store.active_transaction_count(tip.height),
            "window_final_block_hash": tip.block_hash[::-1].hex(),
            "window_final_block_height": tip.height,
            "window_block_count": count,
        }
        if count > 0:
            interval = tip.median_time_past - past.median_time_past
            result["window_interval"] = interval
            final_tx_count = self.store.active_transaction_count(tip.height)
            past_tx_count = self.store.active_transaction_count(past.height)
            window_tx_count = final_tx_count - past_tx_count
            result["window_tx_count"] = window_tx_count
            if interval > 0:
                result["txrate"] = window_tx_count / interval
        return result

    def _block_stats(self, block_value: Any, selected: Any = None) -> dict[str, Any]:
        """Return the per-block statistics exposed by Bitcoin Core's getblockstats."""
        if isinstance(block_value, bool):
            raise RPCError(-8, "Block identifier must be a height or hash")
        if isinstance(block_value, int):
            block_hash = self.store.active_block_hash(block_value) if block_value >= 0 else None
            if block_hash is None:
                raise RPCError(-8, "Block height is outside the active chain")
        else:
            block_hash = self._parse_hash(block_value)
        block = self.store.load_block(block_hash)
        if block is None:
            raise RPCError(-5, "Block not found or block data is unavailable")
        index = self.headers.indexes.get(block_hash)
        undo = self.store.load_undo(block_hash)
        if index is None or undo is None:
            raise RPCError(-5, "Block undo data is unavailable")
        if selected is None:
            names: set[str] | None = None
        elif isinstance(selected, list) and all(isinstance(name, str) for name in selected):
            names = set(selected) if selected else None
        else:
            raise RPCError(-8, "stats must be an array of statistic names")

        tx_sizes: list[int] = []
        fees: list[int] = []
        fee_rates: list[tuple[int, int]] = []
        total_fee = total_out = total_size = total_weight = 0
        input_count = output_count = 0
        segwit_count = segwit_size = segwit_weight = 0
        utxo_size_delta = utxo_size_actual_delta = 0
        actual_utxo_delta = 0
        block_coinbase_repeat = block_hash in self.params.bip30_exception_hashes
        previous_coins = {key: coin for key, coin in undo.spent}
        in_block_coins: dict[tuple[bytes, int], tuple[int, bytes]] = {}
        per_tx_fees: list[int] = []
        per_tx_sizes: list[int] = []

        for tx_position, tx in enumerate(block.transactions):
            coinbase = tx_position == 0
            output_count += len(tx.outputs)
            tx_output_value = sum(output.value for output in tx.outputs)
            for output in tx.outputs:
                serialized_size = len(output.serialize()) + 40
                utxo_size_delta += serialized_size
                unspendable = output.script_pubkey.startswith(b"\x6a")
                ignored_repeat_coinbase = tx_position == 0 and block_coinbase_repeat
                ignored_genesis_coinbase = tx_position == 0 and index.height == 0
                if not unspendable and not ignored_repeat_coinbase and not ignored_genesis_coinbase:
                    actual_utxo_delta += 1
                    utxo_size_actual_delta += serialized_size
            if coinbase:
                for output_index, output in enumerate(tx.outputs):
                    in_block_coins[(tx.txid, output_index)] = (output.value, output.script_pubkey)
                continue

            input_count += len(tx.inputs)
            input_total = 0
            for txin in tx.inputs:
                key = (txin.previous_output.txid, txin.previous_output.index)
                prev = in_block_coins.pop(key, None)
                if prev is not None:
                    value, script_pubkey = prev
                else:
                    coin = previous_coins.pop(key, None)
                    if coin is None:
                        raise RPCError(-32603, "Block undo data does not cover transaction inputs")
                    value, script_pubkey = coin.value, coin.script_pubkey
                input_total += value
                prevout_size = 8 + len(write_compact_size(len(script_pubkey))) + len(script_pubkey) + 40
                utxo_size_delta -= prevout_size
                utxo_size_actual_delta -= prevout_size
                actual_utxo_delta -= 1
            fee = input_total - tx_output_value
            if fee < 0:
                raise RPCError(-32603, "Block contains a transaction with negative fee")
            fees.append(fee)
            per_tx_fees.append(fee)
            raw = tx.serialize(include_witness=True)
            stripped = tx.serialize(include_witness=False)
            size = len(raw)
            weight = len(stripped) * 3 + size
            tx_sizes.append(size)
            per_tx_sizes.append(size)
            total_size += size
            total_weight += weight
            total_out += tx_output_value
            fee_rates.append((fee * 4 // weight if weight else 0, weight))
            total_fee += fee
            if tx.has_witness:
                segwit_count += 1
                segwit_size += size
                segwit_weight += weight
            for output_index, output in enumerate(tx.outputs):
                in_block_coins[(tx.txid, output_index)] = (output.value, output.script_pubkey)

        tx_count = len(block.transactions)
        non_coinbase_count = max(0, tx_count - 1)
        sorted_fees = sorted(fees)
        sorted_sizes = sorted(tx_sizes)
        median_fee = _truncated_median(sorted_fees)
        median_size = _truncated_median(sorted_sizes)
        percentile_values = [0, 0, 0, 0, 0]
        if fee_rates:
            sorted_rates = sorted(fee_rates)
            thresholds = [total_weight / 10, total_weight / 4, total_weight / 2,
                          total_weight * 3 / 4, total_weight * 9 / 10]
            cumulative = 0
            percentile = 0
            for rate, weight in sorted_rates:
                cumulative += weight
                while percentile < 5 and cumulative >= thresholds[percentile]:
                    percentile_values[percentile] = rate
                    percentile += 1
            for position in range(percentile, 5):
                percentile_values[position] = sorted_rates[-1][0]

        minimum_fee = min(fees, default=0)
        maximum_fee = max(fees, default=0)
        min_feerate = min((rate for rate, _weight in fee_rates), default=0)
        max_feerate = max((rate for rate, _weight in fee_rates), default=0)
        stats = {
            "avgfee": total_fee // non_coinbase_count if non_coinbase_count else 0,
            "avgfeerate": total_fee * 4 // total_weight if total_weight else 0,
            "avgtxsize": total_size // non_coinbase_count if non_coinbase_count else 0,
            "blockhash": block_hash[::-1].hex(),
            "feerate_percentiles": percentile_values,
            "height": index.height,
            "ins": input_count,
            "maxfee": maximum_fee,
            "maxfeerate": max_feerate,
            "maxtxsize": max(tx_sizes, default=0),
            "medianfee": median_fee,
            "mediantime": index.median_time_past,
            "mediantxsize": median_size,
            "minfee": minimum_fee,
            "minfeerate": min_feerate,
            "mintxsize": min(tx_sizes, default=0),
            "outs": output_count,
            "subsidy": block_subsidy(index.height, self.params),
            "swtotal_size": segwit_size,
            "swtotal_weight": segwit_weight,
            "swtxs": segwit_count,
            "time": block.header.timestamp,
            "total_out": total_out,
            "total_size": total_size,
            "total_weight": total_weight,
            "totalfee": total_fee,
            "txs": tx_count,
            "utxo_increase": output_count - input_count,
            "utxo_size_inc": utxo_size_delta,
            "utxo_increase_actual": actual_utxo_delta,
            "utxo_size_inc_actual": utxo_size_actual_delta,
        }
        if names is None:
            return stats
        unknown = names - stats.keys()
        if unknown:
            raise RPCError(-8, f"Invalid selected statistic '{min(unknown)}'")
        return {name: stats[name] for name in sorted(names)}

    def _chain_tips(self) -> list[dict[str, Any]]:
        child_parents = {index.header.previous_block for index in self.headers.indexes.values()}
        active_hash = self.store.best_block()
        tips = [
            index for block_hash, index in self.headers.indexes.items()
            if block_hash not in child_parents or block_hash == active_hash
        ]
        result = []
        for tip in tips:
            active_at_height = self.store.active_block_hash(tip.height) == tip.block_hash
            if active_at_height:
                status = "active"
                branch_length = 0
            else:
                active_index = self.headers.indexes.get(active_hash) if active_hash else None
                left, right = active_index, tip
                while left is not None and right is not None and left.height > right.height:
                    left = left.previous
                while left is not None and right is not None and right.height > left.height:
                    right = right.previous
                while left is not right:
                    left = left.previous if left is not None else None
                    right = right.previous if right is not None else None
                branch_length = tip.height - (left.height if left is not None else -1)
                status = "valid-headers" if self.store.has_block(tip.block_hash) else "headers-only"
            result.append({
                "height": tip.height,
                "hash": tip.block_hash[::-1].hex(),
                "branchlen": branch_length,
                "status": status,
            })
        return sorted(result, key=lambda item: (-item["height"], item["hash"]))

    def _ancestors(self, txid: bytes) -> set[bytes]:
        result: set[bytes] = set()
        pending = list(self.mempool.entries[txid].parents)
        while pending:
            current = pending.pop()
            if current not in result and current in self.mempool.entries:
                result.add(current)
                pending.extend(self.mempool.entries[current].parents)
        return result

    def _descendants(self, txid: bytes) -> set[bytes]:
        result: set[bytes] = set()
        pending = list(self.mempool.entries[txid].children)
        while pending:
            current = pending.pop()
            if current not in result and current in self.mempool.entries:
                result.add(current)
                pending.extend(self.mempool.entries[current].children)
        return result

    def _descendant_count(self, txid: bytes) -> int:
        return len(self._descendants(txid)) + 1

    def _mempool_entry_json(self, entry: MempoolEntry) -> dict[str, Any]:
        txid = entry.txid
        ancestors = self._ancestors(txid) | {txid}
        descendants = self._descendants(txid) | {txid}
        ancestor_fee = sum(
            self.mempool.entries[item].modified_fee
            for item in ancestors
        )
        descendant_fee = sum(
            self.mempool.entries[item].modified_fee
            for item in descendants
        )
        return {
            "vsize_adjusted": entry.vsize,
            "vsize": entry.vsize,
            "vsize_bip141": entry.vsize_bip141,
            "weight": entry.weight,
            "time": entry.added_at,
            "height": entry.height,
            "descendantcount": len(descendants),
            "descendantsize": sum(self.mempool.entries[item].vsize for item in descendants),
            "ancestorcount": len(ancestors),
            "ancestorsize": sum(self.mempool.entries[item].vsize for item in ancestors),
            "wtxid": entry.wtxid[::-1].hex(),
            "fees": {
                "base": entry.fee / 100_000_000,
                "modified": entry.modified_fee / 100_000_000,
                "ancestor": ancestor_fee / 100_000_000,
                "descendant": descendant_fee / 100_000_000,
            },
            "depends": [parent[::-1].hex() for parent in sorted(entry.parents)],
            "spentby": [child[::-1].hex() for child in sorted(entry.children)],
            "unbroadcast": txid in self.mempool.unbroadcast_txs,
        }

    def _get_tx_spending_prevout(self, outputs: Any, options: Any) -> list[dict[str, Any]]:
        if not isinstance(outputs, list) or not outputs:
            raise RPCError(-8, "Invalid parameter, outputs are missing")
        if not isinstance(options, dict):
            raise RPCError(-8, "Options must be an object")
        mempool_only = options.get("mempool_only", True)
        include_transaction = options.get("return_spending_tx", False)
        if not isinstance(mempool_only, bool) or not isinstance(include_transaction, bool):
            raise RPCError(-8, "mempool_only and return_spending_tx options must be booleans")

        result = []
        for output in outputs:
            if not isinstance(output, dict) or "txid" not in output or "vout" not in output:
                raise RPCError(-8, "Each output must contain txid and vout")
            txid = self._parse_hash(output["txid"])
            output_index = output["vout"]
            if isinstance(output_index, bool) or not isinstance(output_index, int) or output_index < 0:
                raise RPCError(-8, "vout must be a non-negative integer")
            response = {"txid": txid[::-1].hex(), "vout": output_index}
            spender_id = self.mempool.spent_outpoints.get((txid, output_index))
            if spender_id is not None:
                spending_tx = self.mempool.get(spender_id)
                if spending_tx is not None:
                    response["spendingtxid"] = spender_id[::-1].hex()
                    if include_transaction:
                        response["spendingtx"] = spending_tx.serialize(include_witness=True).hex()
            elif not mempool_only:
                raise RPCError(-32603, "Mempool lacks a relevant spend, and txospenderindex is unavailable")
            result.append(response)
        return result

    @staticmethod
    def _peer_info(peer: PeerConnection, peer_id: int) -> dict[str, Any]:
        remote = peer.handshake.remote_version
        address = peer.address
        host = address[0] if address else ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        result = {
            "id": peer_id,
            "addr": f"{host}:{address[1]}" if address else "",
            "inbound": peer.inbound,
            "connected": peer.established,
            "version": remote.protocol_version if remote else 0,
            "subver": remote.user_agent if remote else "",
            "services": f"{remote.services:016x}" if remote else "0" * 16,
            "startingheight": remote.start_height if remote else -1,
            "minfeefilter": peer.fee_filter / 100_000_000,
            "connection_type": "inbound" if peer.inbound else "outbound-full-relay",
            "transport_protocol_type": "v1",
        }
        if peer.ping_time is not None:
            result["pingtime"] = peer.ping_time
        ping_wait = peer.ping_wait
        if ping_wait is not None:
            result["pingwait"] = ping_wait
        return result

    def _get_txout(self, txid_value: Any, output_index: Any, include_mempool: bool) -> dict[str, Any] | None:
        txid = self._parse_hash(txid_value)
        if not isinstance(output_index, int) or output_index < 0:
            raise RPCError(-8, "Output index must be a non-negative integer")
        key = (txid, output_index)
        coin = self.coins.coins.get(key)
        if include_mempool and key in self.mempool.spent_outpoints:
            return None
        if coin is not None:
            return {
                "bestblock": (self.store.best_block() or bytes(32))[::-1].hex(),
                "confirmations": max(0, self.store.best_height() - coin.height + 1),
                "value": coin.value / 100_000_000,
                "scriptPubKey": {"asm": "", "hex": coin.script_pubkey.hex(), "type": "nonstandard"},
                "coinbase": coin.coinbase,
            }
        if include_mempool:
            tx = self.mempool.get(txid)
            if tx is not None and output_index < len(tx.outputs) and key not in self.mempool.spent_outpoints:
                output = tx.outputs[output_index]
                return {
                    "bestblock": (self.store.best_block() or bytes(32))[::-1].hex(),
                    "confirmations": 0,
                    "value": output.value / 100_000_000,
                    "scriptPubKey": {"asm": "", "hex": output.script_pubkey.hex(), "type": "nonstandard"},
                    "coinbase": False,
                }
        return None

    def _get_raw_transaction(self, txid_value: Any, verbose: bool) -> Any:
        txid = self._parse_hash(txid_value)
        tx = self.mempool.get(txid)
        block_hash = None
        height = None
        if tx is None:
            indexed = self.store.find_transaction(txid)
            if indexed is None:
                raise RPCError(-5, "Transaction not found in mempool or active chain")
            block_hash, height, _position, tx = indexed
        raw = tx.serialize(include_witness=True)
        if not verbose:
            return raw.hex()
        result = {
            "txid": tx.txid_hex,
            "hash": tx.wtxid_hex,
            "version": tx.version,
            "size": len(raw),
            "vsize": (len(tx.serialize(include_witness=False)) * 3 + len(raw) + 3) // 4,
            "locktime": tx.lock_time,
            "hex": raw.hex(),
        }
        if block_hash is not None and height is not None:
            result["blockhash"] = block_hash[::-1].hex()
            result["confirmations"] = self.store.best_height() - height + 1
        return result


@dataclass(slots=True)
class RPCServer:
    """HTTP JSON-RPC endpoint protected by a local cookie credential."""

    rpc: NodeRPC
    cookie_path: Path
    host: str = "127.0.0.1"
    port: int = 8332
    _server: asyncio.AbstractServer | None = None
    _cookie: str = ""

    async def start(self) -> None:
        """Create a cookie and start listening for authenticated HTTP requests."""
        if self._server is not None:
            raise RuntimeError("RPC server is already running")
        self.cookie_path.parent.mkdir(parents=True, exist_ok=True)
        self._cookie = "__cookie__:" + secrets.token_urlsafe(32)
        self.cookie_path.write_text(self._cookie, encoding="ascii")
        if os.name != "nt":
            self.cookie_path.chmod(0o600)
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def close(self) -> None:
        """Stop accepting requests and remove the generated cookie file."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self.cookie_path.exists():
            self.cookie_path.unlink()
        self._cookie = ""

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        status = "200 OK"
        extra_headers = ""
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            if len(request) > MAX_HTTP_HEADER:
                raise ValueError("HTTP header exceeds limit")
            lines = request.decode("iso-8859-1").split("\r\n")
            if not lines or not lines[0].startswith("POST "):
                raise ValueError("only HTTP POST requests are supported")
            headers = {}
            for line in lines[1:]:
                if not line:
                    break
                name, separator, value = line.partition(":")
                if not separator:
                    raise ValueError("malformed HTTP header")
                headers[name.strip().lower()] = value.strip()
            if not self._authorized(headers.get("authorization", "")):
                status = "401 Unauthorized"
                extra_headers = "WWW-Authenticate: Basic realm=\"bitcoin-rpc\"\r\n"
                body = json.dumps({"error": {"code": -32600, "message": "Unauthorized"}, "id": None}).encode()
            else:
                content_length = int(headers.get("content-length", "-1"))
                if content_length < 0 or content_length > MAX_RPC_BODY:
                    raise ValueError("invalid or oversized Content-Length")
                request_body = await reader.readexactly(content_length)
                body = await self._dispatch_body(request_body)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            status = "400 Bad Request"
            body = json.dumps({"error": {"code": -32700, "message": str(exc)}, "id": None}).encode()
        writer.write(
            f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n{extra_headers}\r\n".encode("ascii")
            + body
        )
        try:
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    def _authorized(self, header: str) -> bool:
        scheme, _, encoded = header.partition(" ")
        if scheme.lower() != "basic" or not encoded:
            return False
        try:
            credential = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(credential, self._cookie)

    async def _dispatch_body(self, body: bytes) -> bytes:
        try:
            request = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON-RPC request") from exc
        if isinstance(request, list):
            if not request:
                return _rpc_error(None, -32600, "Empty batch request")
            responses = [await self._dispatch_one(item) for item in request]
            return json.dumps([response for response in responses if response is not None], separators=(",", ":")).encode()
        response = await self._dispatch_one(request)
        return json.dumps(response, separators=(",", ":")).encode()

    async def _dispatch_one(self, request: Any) -> dict[str, Any] | None:
        if not isinstance(request, dict) or not isinstance(request.get("method"), str):
            return {"result": None, "error": {"code": -32600, "message": "Invalid Request"}, "id": None}
        request_id = request.get("id")
        try:
            result = await self.rpc.call(request["method"], request.get("params"))
            error = None
        except RPCError as exc:
            result = None
            error = {"code": exc.code, "message": str(exc)}
        except Exception as exc:
            result = None
            error = {"code": -32603, "message": str(exc)}
        if "id" not in request:
            return None
        return {"result": result, "error": error, "id": request_id}


def _rpc_error(request_id: Any, code: int, message: str) -> bytes:
    return json.dumps({"result": None, "error": {"code": code, "message": message}, "id": request_id}).encode()
