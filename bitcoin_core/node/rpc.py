"""Authenticated JSON-RPC methods and a small asynchronous HTTP server."""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bitcoin_core.consensus.chainstate import CoinsView
from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.consensus.pow import decode_compact_target
from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.node.chain import HeaderChain
from bitcoin_core.node.mempool import Mempool, MempoolError
from bitcoin_core.node.relay import MempoolRelay
from bitcoin_core.node.storage import SQLiteNodeStore
from bitcoin_core.primitives.block import BlockHeader
from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.serialization.compact_size import write_compact_size

MAX_RPC_BODY = 16 * 1024 * 1024
MAX_HTTP_HEADER = 64 * 1024


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

    async def call(self, method: str, params: list[Any] | dict[str, Any] | None = None) -> Any:
        params = [] if params is None else params
        if method == "getblockcount":
            return self.store.best_height()
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
                bool(self._param(params, 1, "verbose", False)),
            )
        if method == "getrawmempool":
            verbose = bool(self._param(params, 0, "verbose", False))
            if not verbose:
                return [entry.txid[::-1].hex() for entry in self.mempool.entries.values()]
            return {
                entry.txid[::-1].hex(): {
                    "size": entry.vsize,
                    "fee": entry.fee / 100_000_000,
                    "time": entry.added_at,
                    "depends": [parent[::-1].hex() for parent in sorted(entry.parents)],
                }
                for entry in self.mempool.entries.values()
            }
        if method == "getmempoolinfo":
            return {
                "loaded": True,
                "size": len(self.mempool.entries),
                "bytes": self.mempool.total_vbytes,
                "usage": self.mempool.total_vbytes,
                "maxmempool": self.mempool.max_vbytes,
                "mempoolminfee": self.mempool.min_relay_fee_per_kvb / 100_000_000,
                "minrelaytxfee": self.mempool.min_relay_fee_per_kvb / 100_000_000,
            }
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
                entry = await self.relay.submit(tx, self.peers())
            except MempoolError as exc:
                raise RPCError(-26, str(exc)) from exc
            return entry.txid[::-1].hex()
        if method == "getnetworkinfo":
            return {
                "version": 1,
                "subversion": "/bitcoin-py:0.1/",
                "protocolversion": 70_016,
                "networkactive": True,
            }
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
        return result

    def _blockchain_info(self) -> dict[str, Any]:
        tip = self.headers.tip
        best = self.store.best_block()
        return {
            "chain": self.network_name,
            "blocks": self.store.best_height(),
            "headers": tip.height if tip else -1,
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
        if tx is None:
            raise RPCError(-5, "Transaction not found in mempool")
        raw = tx.serialize(include_witness=True)
        if not verbose:
            return raw.hex()
        return {
            "txid": tx.txid_hex,
            "hash": tx.wtxid_hex,
            "version": tx.version,
            "size": len(raw),
            "vsize": (len(tx.serialize(include_witness=False)) * 3 + len(raw) + 3) // 4,
            "locktime": tx.lock_time,
            "hex": raw.hex(),
        }


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
