"""Authenticated JSON-RPC methods and a small asynchronous HTTP server."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import math
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bitcoin_core.consensus.chainstate import CoinsView
from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.consensus.pow import decode_compact_target
from bitcoin_core.consensus.subsidy import block_subsidy
from bitcoin_core.consensus.versionbits import NEVER_ACTIVE, ThresholdState, VersionBits
from bitcoin_core.network.connection import PeerConnection
from bitcoin_core.network.addrman import AddressBook
from bitcoin_core.network.banman import BanManager, parse_subnet
from bitcoin_core.network.version import NODE_COMPACT_FILTERS, NODE_NETWORK
from bitcoin_core.node.chain import HeaderChain, expected_work_bits
from bitcoin_core.node.block_policy_estimator import BlockPolicyEstimator
from bitcoin_core.node.fee_estimator import MempoolFeeEstimator
from bitcoin_core.node.mempool import Mempool, MempoolEntry, MempoolError
from bitcoin_core.node.mempool_persistence import MempoolLoadResult
from bitcoin_core.node.mining import create_block_template
from bitcoin_core.node.relay import MempoolRelay
from bitcoin_core.node.storage import SQLiteNodeStore
from bitcoin_core.node.utxo_stats import calculate_utxo_stats
from bitcoin_core.primitives.block import Block, BlockHeader
from bitcoin_core.primitives.transaction import Transaction
from bitcoin_core.script.describe import script_pubkey_json, script_to_asm
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
    network_totals: Callable[[], tuple[int, int]] = field(default=lambda: (0, 0))
    address_book: AddressBook | None = None
    network_active: Callable[[], bool] = field(default=lambda: True)
    set_network_active: Callable[[bool], bool] | None = None
    disconnect_peer: Callable[[str | None, int | None], Awaitable[bool]] | None = None
    manage_added_node: Callable[[str, str], Awaitable[None]] | None = None
    added_node_info: Callable[[str | None], list[dict[str, Any]]] | None = None
    ban_manager: BanManager | None = None
    disconnect_banned: Callable[[Any], Awaitable[None]] | None = None
    peer_inflight_blocks: Callable[[PeerConnection], list[int]] = field(default=lambda _peer: [])
    fee_estimator: MempoolFeeEstimator | None = None
    block_policy_estimator: BlockPolicyEstimator | None = None
    _versionbits: dict[str, VersionBits] = field(default_factory=dict, init=False)

    async def call(self, method: str, params: list[Any] | dict[str, Any] | None = None) -> Any:
        params = [] if params is None else params
        if method == "getblockcount":
            return self.store.best_height()
        if method == "getdifficulty":
            return self._active_difficulty()
        if method == "getnetworkhashps":
            return self._network_hash_ps(
                self._param(params, 0, "nblocks", 120),
                self._param(params, 1, "height", -1),
            )
        if method == "getmininginfo":
            return self._mining_info()
        if method == "getchaintips":
            return self._chain_tips()
        if method == "getdeploymentinfo":
            return self._deployment_info(self._param(params, 0, "blockhash"))
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
            longpollid = request.get("longpollid")
            if longpollid is not None:
                await self._wait_for_template_change(longpollid)
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
        if method == "testmempoolaccept":
            return self._test_mempool_accept(
                self._param(params, 0, "rawtxs"),
                self._param(params, 1, "maxfeerate", 0.1),
                self._param(params, 2, "maxburnamount", 0.0),
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
        if method == "estimatesmartfee":
            return self._estimate_smart_fee(
                self._param(params, 0, "conf_target"),
                self._param(params, 1, "estimate_mode", "economical"),
                self._param(params, 2, "options", {}),
            )
        if method == "estimaterawfee":
            return self._estimate_raw_fee(
                self._param(params, 0, "conf_target"),
                self._param(params, 1, "threshold", 0.95),
            )
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
        if method in ("getmempoolancestors", "getmempooldescendants"):
            txid = self._parse_hash(self._param(params, 0, "txid"))
            if txid not in self.mempool.entries:
                raise RPCError(-5, "Transaction not in mempool")
            verbose = self._param(params, 1, "verbose", False)
            if not isinstance(verbose, bool):
                raise RPCError(-3, "verbose must be a boolean")
            related = (
                self._ancestors(txid)
                if method == "getmempoolancestors"
                else self._descendants(txid)
            )
            if not verbose:
                return [item[::-1].hex() for item in sorted(related)]
            return {
                item[::-1].hex(): self._mempool_entry_json(self.mempool.entries[item])
                for item in sorted(related)
            }
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
            services = NODE_NETWORK | NODE_COMPACT_FILTERS
            service_names = []
            if services & NODE_NETWORK:
                service_names.append("NETWORK")
            if services & NODE_COMPACT_FILTERS:
                service_names.append("COMPACT_FILTERS")
            relay_fee = self.mempool.min_relay_fee_per_kvb / 100_000_000
            peers = self.peers()
            time_offsets = [
                peer.time_offset
                for peer in peers
                if peer.established and not peer.inbound and peer.time_offset is not None
            ]
            return {
                "version": 1,
                "subversion": "/bitcoin-py:0.1/",
                "protocolversion": 70_016,
                "localservices": f"{services:016x}",
                "localservicesnames": service_names,
                "localrelay": True,
                "timeoffset": _truncated_median(time_offsets),
                "networkactive": self.network_active(),
                "connections": sum(peer.established for peer in peers),
                "connections_in": sum(peer.established and peer.inbound for peer in peers),
                "connections_out": sum(peer.established and not peer.inbound for peer in peers),
                "relayfee": relay_fee,
                "incrementalfee": relay_fee,
                "networks": [
                    {
                        "name": name,
                        "limited": not reachable,
                        "reachable": reachable,
                        "proxy": "",
                        "proxy_randomize_credentials": False,
                    }
                    for name, reachable in (
                        ("ipv4", True),
                        ("ipv6", True),
                        ("onion", False),
                        ("i2p", False),
                        ("cjdns", False),
                    )
                ],
                "localaddresses": [],
                "warnings": [],
            }
        if method == "getconnectioncount":
            return sum(peer.established for peer in self.peers())
        if method == "ping":
            await asyncio.gather(
                *(peer.request_ping() for peer in self.peers() if peer.established),
                return_exceptions=True,
            )
            return None
        if method == "getnettotals":
            peers = self.peers()
            sent_total, received_total = self.network_totals()
            return {
                "totalbytesrecv": received_total + sum(peer.bytes_received for peer in peers),
                "totalbytessent": sent_total + sum(peer.bytes_sent for peer in peers),
                "timemillis": time.time_ns() // 1_000_000,
                "uploadtarget": {
                    "timeframe": 86_400,
                    "target": 0,
                    "target_reached": False,
                    "serve_historical_blocks": True,
                    "bytes_left_in_cycle": 0,
                    "time_left_in_cycle": 0,
                },
            }
        if method == "getpeerinfo":
            return [self._peer_info(peer, peer_id) for peer_id, peer in enumerate(self.peers())]
        if method == "getnodeaddresses":
            count = self._param(params, 0, "count", 1)
            network = self._param(params, 1, "network")
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or not 0 <= count <= 0x7FFFFFFF
            ):
                raise RPCError(-8, "Address count out of range")
            network_ids = {"ipv4": 1, "ipv6": 2, "onion": 4, "i2p": 5, "cjdns": 6}
            if network is not None and (
                not isinstance(network, str) or network.lower() not in network_ids
            ):
                raise RPCError(-8, f"Network not recognized: {network}")
            if self.address_book is None:
                return []
            records = self.address_book.known(
                count,
                network_id=network_ids[network.lower()] if network is not None else None,
            )
            return [self._node_address_info(record) for record in records]
        if method == "setnetworkactive":
            state = self._param(params, 0, "state")
            if not isinstance(state, bool):
                raise RPCError(-8, "state must be a boolean")
            if self.set_network_active is None:
                raise RPCError(-32603, "P2P network control is not configured")
            return self.set_network_active(state)
        if method == "disconnectnode":
            address = self._param(params, 0, "address")
            node_id = self._param(params, 1, "nodeid")
            if address is not None and not isinstance(address, str):
                raise RPCError(-32602, "address must be a string")
            if node_id is not None and (
                isinstance(node_id, bool) or not isinstance(node_id, int) or node_id < 0
            ):
                raise RPCError(-32602, "nodeid must be a non-negative integer")
            if not (
                (address not in (None, "") and node_id is None)
                or (node_id is not None and address in (None, ""))
            ):
                raise RPCError(-32602, "Only one of address and nodeid should be provided")
            if self.disconnect_peer is None:
                raise RPCError(-32603, "P2P peer control is not configured")
            if not await self.disconnect_peer(address, node_id):
                raise RPCError(-29, "Node not found in connected nodes")
            return None
        if method == "addnode":
            node = self._param(params, 0, "node")
            command = self._param(params, 1, "command")
            v2transport = self._param(params, 2, "v2transport", False)
            if not isinstance(node, str) or not node.strip():
                raise RPCError(-8, "Node address cannot be empty")
            if not isinstance(command, str) or command not in {"add", "remove", "onetry"}:
                raise RPCError(-8, "command must be add, remove, or onetry")
            if not isinstance(v2transport, bool):
                raise RPCError(-8, "v2transport must be a boolean")
            if v2transport:
                raise RPCError(-8, "v2 transport is not enabled")
            if self.manage_added_node is None:
                raise RPCError(-32603, "Added-node management is not configured")
            try:
                await self.manage_added_node(node, command)
            except ValueError as exc:
                code = -23 if "already added" in str(exc).lower() else -24 if command == "remove" else -8
                raise RPCError(code, str(exc)) from exc
            return None
        if method == "getaddednodeinfo":
            node = self._param(params, 0, "node")
            if node is not None and not isinstance(node, str):
                raise RPCError(-3, "node must be a string")
            if self.added_node_info is None:
                raise RPCError(-32603, "Added-node information is not configured")
            try:
                return self.added_node_info(node)
            except ValueError as exc:
                raise RPCError(-24, str(exc)) from exc
        if method == "setban":
            subnet_text = self._param(params, 0, "subnet")
            command = self._param(params, 1, "command")
            bantime = self._param(params, 2, "bantime", 0)
            absolute = self._param(params, 3, "absolute", False)
            bantime = 0 if bantime is None else bantime
            absolute = False if absolute is None else absolute
            if self.ban_manager is None:
                raise RPCError(-32603, "Peer banning is not configured")
            if not isinstance(subnet_text, str):
                raise RPCError(-32602, "subnet must be a string")
            if command not in {"add", "remove"}:
                raise RPCError(-32602, "command must be add or remove")
            if isinstance(bantime, bool) or not isinstance(bantime, int) or bantime < 0:
                raise RPCError(-8, "bantime must be a non-negative integer")
            if not isinstance(absolute, bool):
                raise RPCError(-3, "absolute must be a boolean")
            try:
                subnet = parse_subnet(subnet_text)
            except ValueError as exc:
                raise RPCError(-30, str(exc)) from exc
            if command == "add":
                if any(record.subnet == subnet for record in self.ban_manager.list()):
                    raise RPCError(-23, "IP/Subnet already banned")
                try:
                    self.ban_manager.ban(subnet, bantime, absolute=absolute)
                except ValueError as exc:
                    raise RPCError(-8, str(exc)) from exc
                if self.disconnect_banned is not None:
                    await self.disconnect_banned(subnet)
            elif not self.ban_manager.unban(subnet):
                raise RPCError(-30, "Requested IP/Subnet was not previously banned")
            return None
        if method == "listbanned":
            if self.ban_manager is None:
                raise RPCError(-32603, "Peer banning is not configured")
            now = int(time.time())
            return [record.to_rpc(now) for record in self.ban_manager.list(now=now)]
        if method == "clearbanned":
            if self.ban_manager is None:
                raise RPCError(-32603, "Peer banning is not configured")
            self.ban_manager.clear()
            return None
        raise RPCError(-32601, f"Method not found: {method}")

    @staticmethod
    def _node_address_info(record) -> dict[str, Any]:
        if record.network_id == 1:
            address = str(ipaddress.IPv4Address(record.address_bytes))
            network = "ipv4"
        elif record.network_id == 2:
            address = str(ipaddress.IPv6Address(record.address_bytes))
            network = "ipv6"
        elif record.network_id == 4:
            key = record.address_bytes
            checksum = hashlib.sha3_256(b".onion checksum" + key + b"\x03").digest()[:2]
            address = base64.b32encode(key + checksum + b"\x03").decode("ascii").lower().rstrip("=") + ".onion"
            network = "onion"
        elif record.network_id == 5:
            address = base64.b32encode(record.address_bytes).decode("ascii").lower().rstrip("=") + ".b32.i2p"
            network = "i2p"
        elif record.network_id == 6:
            address = str(ipaddress.IPv6Address(record.address_bytes))
            network = "cjdns"
        else:
            address = record.address_bytes.hex()
            network = "unknown"
        return {
            "time": record.timestamp,
            "services": record.services,
            "address": address,
            "port": record.port,
            "network": network,
        }

    async def _wait_for_template_change(self, longpollid: Any) -> None:
        """Wait until the active tip or transaction pool changes from a GBT ID."""
        if not isinstance(longpollid, str) or len(longpollid) <= 64:
            raise RPCError(-8, "longpollid must contain a block hash and mempool sequence")
        try:
            block_hash = bytes.fromhex(longpollid[:64])
        except ValueError as exc:
            raise RPCError(-8, "longpollid contains an invalid block hash") from exc
        sequence_text = longpollid[64:]
        if (
            len(block_hash) != 32
            or len(sequence_text) > 20
            or not sequence_text.isascii()
            or not sequence_text.isdecimal()
        ):
            raise RPCError(-8, "longpollid contains an invalid mempool sequence")
        sequence = int(sequence_text)

        while True:
            current_tip = self.store.best_block()
            if current_tip != block_hash[::-1] or self.mempool.transactions_updated != sequence:
                return
            await asyncio.sleep(0.5)

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

    def _estimate_smart_fee(self, target: Any, mode: Any, options: Any) -> dict[str, Any]:
        """Estimate a short-horizon fee from recent mempool-representative blocks."""
        if isinstance(target, bool) or not isinstance(target, int) or not 1 <= target <= 1_008:
            raise RPCError(-8, "Confirmation target must be between 1 and 1008 blocks")
        if not isinstance(mode, str) or mode.lower() not in ("unset", "economical", "conservative"):
            raise RPCError(-8, "Invalid estimate_mode; use unset, economical, or conservative")
        if options is None:
            options = {}
        if not isinstance(options, dict):
            raise RPCError(-3, "options must be an object")
        if set(options) - {"fee_rate_estimator", "verbosity"}:
            raise RPCError(-8, "Unknown estimatesmartfee option")
        estimator_type = options.get("fee_rate_estimator", "auto")
        if not isinstance(estimator_type, str) or estimator_type not in (
            "auto",
            "mempool_policy",
            "block_policy",
        ):
            raise RPCError(-8, 'fee_rate_estimator must be "auto", "block_policy", or "mempool_policy"')
        verbosity = options.get("verbosity", 1)
        if isinstance(verbosity, bool) or not isinstance(verbosity, int):
            raise RPCError(-3, "verbosity must be an integer")

        conservative = mode.lower() == "conservative"
        policy_estimator = self.block_policy_estimator
        mempool_estimator = self.fee_estimator
        policy_rate = None
        policy_target = target
        if policy_estimator is not None:
            policy_rate, policy_target = policy_estimator.estimate_smart_fee(
                target, conservative=conservative
            )
        mempool_rate = None
        if mempool_estimator is not None:
            estimated_sat_vb, _error = mempool_estimator.estimate(conservative=conservative)
            if estimated_sat_vb is not None:
                mempool_rate = estimated_sat_vb * 1_000

        selected_rate: float | None
        selected_target: int
        selected_estimator: str | None = None
        if estimator_type == "block_policy":
            selected_rate, selected_target = policy_rate, policy_target
            selected_estimator = "block_policy"
        elif estimator_type == "mempool_policy":
            selected_rate, selected_target = mempool_rate, 2
            selected_estimator = "mempool_policy"
        else:
            if policy_rate is None:
                selected_rate, selected_target = None, policy_target
            elif mempool_rate is not None and mempool_rate < policy_rate:
                selected_rate, selected_target = mempool_rate, 2
                selected_estimator = "mempool_policy"
            else:
                selected_rate, selected_target = policy_rate, policy_target
                selected_estimator = "block_policy"

        result: dict[str, Any] = {"blocks": selected_target}
        if selected_rate is None:
            result["errors"] = ["Insufficient data or no feerate found"]
        else:
            fee_per_kvb = max(int(selected_rate), self.mempool.min_relay_fee_per_kvb)
            result["feerate"] = fee_per_kvb / 100_000_000
            if estimator_type == "auto":
                result["estimator"] = selected_estimator
        if verbosity >= 2 and mempool_estimator is not None:
            result["mempool_health_statistics"] = [
                {
                    "block_height": block.height,
                    "block_weight": block.block_weight,
                    "mempool_txs_weight": block.mempool_txs_weight,
                }
                for block in reversed(mempool_estimator.recent_blocks())
            ]
        return result

    def _estimate_raw_fee(self, target: Any, threshold: Any) -> dict[str, Any]:
        """Return the detailed fee-bucket data used by the block-policy estimator."""
        if isinstance(target, bool) or not isinstance(target, int) or not 1 <= target <= 1_008:
            raise RPCError(-8, "Confirmation target must be between 1 and 1008 blocks")
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise RPCError(-3, "threshold must be numeric")
        if not math.isfinite(threshold) or not 0 <= threshold <= 1:
            raise RPCError(-8, "Invalid threshold")
        if self.block_policy_estimator is None:
            raise RPCError(-32603, "Block-policy fee estimation is not configured")

        def rounded(value: float, decimals: int = 0) -> float:
            factor = 10**decimals
            return math.floor(value * factor + 0.5) / factor

        def bucket_json(bucket) -> dict[str, float]:
            return {
                "startrange": rounded(bucket.start),
                "endrange": rounded(bucket.end),
                "withintarget": rounded(bucket.within_target, 2),
                "totalconfirmed": rounded(bucket.total_confirmed, 2),
                "inmempool": rounded(bucket.in_mempool, 2),
                "leftmempool": rounded(bucket.left_mempool, 2),
            }

        estimator = self.block_policy_estimator
        result: dict[str, Any] = {}
        for name, maximum in (("short", 12), ("medium", 48), ("long", 1_008)):
            if target > maximum:
                continue
            feerate, stats = estimator.estimate_raw_fee(target, float(threshold), name)
            item: dict[str, Any] = {"decay": stats.decay, "scale": stats.scale}
            if feerate > 0:
                item["feerate"] = feerate / 100_000_000
                item["pass"] = bucket_json(stats.pass_bucket)
                if stats.fail_bucket.start != -1:
                    item["fail"] = bucket_json(stats.fail_bucket)
            else:
                item["fail"] = bucket_json(stats.fail_bucket)
                item["errors"] = ["Insufficient data or no feerate found which meets threshold"]
            result[name] = item
        return result

    def _deployment_info(self, block_hash_value: Any = None) -> dict[str, Any]:
        """Report BIP9 state and signalling statistics for a selected block."""
        if block_hash_value is None:
            best = self.store.best_block()
            index = self.headers.indexes.get(best) if best is not None else None
        else:
            block_hash = self._parse_hash(block_hash_value)
            index = self.headers.indexes.get(block_hash)
            if index is None:
                raise RPCError(-5, "Block not found")
        if index is None:
            raise RPCError(-32603, "Active chain is unavailable")

        deployments: dict[str, Any] = {}
        for name, deployment in self.params.versionbits_deployments:
            if deployment.start_time == NEVER_ACTIVE:
                continue
            checker = self._versionbits.setdefault(name, VersionBits(deployment))
            info = checker.info(index)
            bip9: dict[str, Any] = {
                "start_time": deployment.start_time,
                "timeout": deployment.timeout,
                "min_activation_height": deployment.min_activation_height,
                "status": info.current_state.value,
                "since": info.since,
                "status_next": info.next_state.value,
            }
            active = False
            if info.active_since is not None:
                bip9["height"] = info.active_since
                active = info.active_since <= index.height + 1
            if info.stats is not None:
                stats = info.stats
                bip9["bit"] = deployment.bit
                statistics: dict[str, Any] = {
                    "period": stats.period,
                    "elapsed": stats.elapsed,
                    "count": stats.count,
                }
                if stats.threshold > 0 or stats.possible:
                    statistics["threshold"] = stats.threshold
                    statistics["possible"] = stats.possible
                bip9["statistics"] = statistics
                bip9["signalling"] = "".join("#" if signalled else "-" for signalled in stats.signalling_blocks)
            deployments[name] = {"type": "bip9", "active": active, "bip9": bip9}
        return {
            "hash": index.block_hash[::-1].hex(),
            "height": index.height,
            "deployments": deployments,
        }

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

    def _transaction_json(self, tx: Transaction) -> dict[str, Any]:
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
                     "scriptSig": {"asm": script_to_asm(txin.script_sig), "hex": txin.script_sig.hex()},
                     "txinwitness": [item.hex() for item in txin.witness] if txin.witness else [],
                     "sequence": txin.sequence,
                 })
                for txin in tx.inputs
            ],
            "vout": [
                {
                    "value": output.value / 100_000_000,
                    "n": index,
                    "scriptPubKey": script_pubkey_json(output.script_pubkey, self.network_name),
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
        block_position = None
        if tx is None:
            indexed = self.store.find_transaction(txid)
            if indexed is None or (requested_block is not None and indexed[0] != requested_block):
                raise RPCError(-5, "Transaction not found in mempool or specified block")
            block_hash, height, block_position, tx = indexed
        raw = tx.serialize(include_witness=True)
        if verbosity is False or verbosity == 0:
            return raw.hex()
        result = self._transaction_json(tx)
        result["hex"] = raw.hex()
        if verbosity == 2:
            result["vin"] = [
                {
                    **item,
                    "prevout": self._prevout_json(
                        txin.previous_output.txid,
                        txin.previous_output.index,
                        block_hash=block_hash,
                        block_position=block_position,
                    ),
                }
                if not txin.previous_output.is_null else item
                for item, txin in zip(result["vin"], tx.inputs)
            ]
        if block_hash is not None and height is not None:
            result["blockhash"] = block_hash[::-1].hex()
            result["confirmations"] = self.store.best_height() - height + 1
        return result

    def _prevout_json(
        self,
        txid: bytes,
        output_index: int,
        *,
        block_hash: bytes | None = None,
        block_position: int | None = None,
    ) -> dict[str, Any] | None:
        block_coin = self.coins.coins.get((txid, output_index))
        parent = self.mempool.get(txid)
        if block_coin is not None:
            return {"value": block_coin.value / 100_000_000,
                    "scriptPubKey": script_pubkey_json(block_coin.script_pubkey, self.network_name)}
        if parent is not None and output_index < len(parent.outputs):
            output = parent.outputs[output_index]
            return {"value": output.value / 100_000_000,
                    "scriptPubKey": script_pubkey_json(output.script_pubkey, self.network_name)}
        if block_hash is not None:
            undo = self.store.load_undo(block_hash)
            if undo is not None:
                coin = next(
                    (coin for outpoint, coin in undo.spent if outpoint == (txid, output_index)),
                    None,
                )
                if coin is not None:
                    return {
                        "value": coin.value / 100_000_000,
                        "scriptPubKey": script_pubkey_json(coin.script_pubkey, self.network_name),
                    }
            if block_position is not None:
                block = self.store.load_block(block_hash)
                if block is not None:
                    for parent_tx in block.transactions[:block_position]:
                        if parent_tx.txid == txid and output_index < len(parent_tx.outputs):
                            output = parent_tx.outputs[output_index]
                            return {
                                "value": output.value / 100_000_000,
                                "scriptPubKey": script_pubkey_json(output.script_pubkey, self.network_name),
                            }
        return None

    def _get_block(self, block_hash_value: Any, verbosity: Any) -> Any:
        block_hash = self._parse_hash(block_hash_value)
        block = self.store.load_block(block_hash)
        if block is None:
            raise RPCError(-5, "Block not found")
        if not isinstance(verbosity, (bool, int)) or verbosity not in (0, 1, 2, 3, False, True):
            raise RPCError(-8, "Block verbosity must be 0, 1, 2, or 3")
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
        elif verbosity == 3:
            result["tx"] = self._block_transactions_with_prevouts(block_hash, block)
        return result

    def _block_transactions_with_prevouts(self, block_hash: bytes, block: Block) -> list[dict[str, Any]]:
        """Build verbosity-3 transaction objects using block undo and intra-block outputs."""
        undo = self.store.load_undo(block_hash)
        if undo is None:
            raise RPCError(-8, "Undo data is unavailable for this block")
        spent = dict(undo.spent)
        outputs: dict[tuple[bytes, int], tuple[int, bytes, bool, int]] = {}
        transactions = []
        for tx_index, transaction in enumerate(block.transactions):
            tx_json = self._transaction_json(transaction)
            if tx_index:
                inputs = []
                for txin, input_json in zip(transaction.inputs, tx_json["vin"]):
                    outpoint = txin.previous_output
                    coin = spent.get((outpoint.txid, outpoint.index))
                    if coin is not None:
                        value = (coin.value, coin.script_pubkey, coin.coinbase, coin.height)
                    else:
                        value = outputs.get((outpoint.txid, outpoint.index))
                    if value is None:
                        raise RPCError(-32603, "Undo data does not contain a transaction prevout")
                    amount, script, generated, height = value
                    inputs.append({
                        **input_json,
                        "prevout": {
                            "generated": generated,
                            "height": height,
                            "value": amount / 100_000_000,
                            "scriptPubKey": script_pubkey_json(script, self.network_name),
                        },
                    })
                tx_json["vin"] = inputs
            transactions.append(tx_json)
            for output_index, txout in enumerate(transaction.outputs):
                outputs[(transaction.txid, output_index)] = (
                    txout.value,
                    txout.script_pubkey,
                    tx_index == 0,
                    undo.height,
                )
        return transactions

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
        if not isinstance(hash_type, str) or hash_type not in ("hash_serialized_3", "muhash", "none"):
            raise RPCError(-8, f"'{hash_type}' is not a valid hash_type")
        if not isinstance(use_index, bool):
            raise RPCError(-8, "use_index must be a boolean")
        best_hash = self.store.best_block()
        if best_hash is None:
            raise RPCError(-32603, "Active chain is unavailable")

        height = self.store.best_height()
        block_hash = best_hash
        view = self.coins
        if hash_or_height is not None:
            if isinstance(hash_or_height, bool):
                raise RPCError(-8, "hash_or_height must be a block height or hash")
            if isinstance(hash_or_height, int):
                if hash_or_height < 0:
                    raise RPCError(-8, "Block height must be non-negative")
                height = hash_or_height
                block_hash = self.store.active_block_hash(height)
                if block_hash is None:
                    raise RPCError(-8, "Block height is outside the active chain")
            elif isinstance(hash_or_height, str):
                block_hash = self._parse_hash(hash_or_height)
                header_height = self.store.header_height(block_hash)
                if header_height is None:
                    raise RPCError(-5, "Block not found")
                height = header_height
                if self.store.active_block_hash(height) != block_hash:
                    raise RPCError(-8, "Block is not in the active chain")
            else:
                raise RPCError(-8, "hash_or_height must be a block height or hash")

        if height != self.store.best_height():
            view = CoinsView(self.coins.coins.copy())
            for disconnect_height in range(self.store.best_height(), height, -1):
                active_hash = self.store.active_block_hash(disconnect_height)
                undo = self.store.load_undo(active_hash) if active_hash is not None else None
                if undo is None:
                    raise RPCError(-8, f"Undo data is unavailable at height {disconnect_height}")
                for outpoint in reversed(undo.created):
                    view.coins.pop(outpoint, None)
                for outpoint, coin in undo.spent:
                    if outpoint in view.coins:
                        raise RPCError(-32603, "Undo data conflicts with the reconstructed UTXO set")
                    view.coins[outpoint] = coin
        try:
            return calculate_utxo_stats(self.store, block_hash, height, hash_type, coins=view)
        except (OSError, ValueError) as exc:
            raise RPCError(-32603, f"Unable to compute UTXO statistics: {exc}") from exc

    def _blockchain_info(self) -> dict[str, Any]:
        best = self.store.best_block()
        tip = self.headers.indexes.get(best) if best is not None else None
        header_tip = self.headers.tip
        height = self.store.best_height()
        buried_forks = {
            "bip16": self.params.p2sh_height,
            "bip34": self.params.bip34_height,
            "bip66": self.params.bip66_height,
            "bip65": self.params.bip65_height,
            "csv": self.params.csv_height,
            "segwit": self.params.segwit_height,
        }
        result = {
            "chain": self.network_name,
            "blocks": height,
            "headers": header_tip.height if header_tip else -1,
            "bestblockhash": best[::-1].hex() if best else "0" * 64,
            "difficulty": self._active_difficulty(),
            "chainwork": f"{tip.chainwork:064x}" if tip else "0" * 64,
            "pruned": False,
            "softforks": {
                name: {"type": "buried", "active": height >= activation, "height": activation}
                for name, activation in buried_forks.items()
                if activation is not None
            },
        }
        if self.params.signet_challenge:
            result["signet_challenge"] = self.params.signet_challenge.hex()
        return result

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

    def _network_hash_ps(self, lookup: Any, height: Any) -> float:
        """Estimate hashes per second from active-chain work and timestamps."""
        if isinstance(lookup, bool) or not isinstance(lookup, int) or lookup < -1 or lookup == 0:
            raise RPCError(-8, "nblocks must be a positive number or -1")
        if isinstance(height, bool) or not isinstance(height, int) or height < -1:
            raise RPCError(-8, "height must be -1 or a non-negative block height")
        tip_hash = self.store.best_block()
        tip = self.headers.indexes.get(tip_hash) if tip_hash is not None else None
        if tip is None:
            return 0.0
        if height > tip.height:
            raise RPCError(-8, "Block does not exist at specified height")
        block = tip if height == -1 else tip.ancestor(height)
        if block is None or block.height == 0:
            return 0.0
        if lookup == -1:
            lookup = block.height % self.params.difficulty_adjustment_interval + 1
        lookup = min(lookup, block.height)
        first = block.ancestor(block.height - lookup)
        if first is None:
            return 0.0
        timestamps = []
        cursor = block
        for _ in range(lookup + 1):
            timestamps.append(cursor.header.timestamp)
            if cursor is first:
                break
            if cursor.previous is None:
                break
            cursor = cursor.previous
        elapsed = max(timestamps) - min(timestamps)
        if elapsed == 0:
            return 0.0
        return (block.chainwork - first.chainwork) / elapsed

    def _mining_info(self) -> dict[str, Any]:
        """Return mining status and current/next proof-of-work targets."""
        best_hash = self.store.best_block()
        tip = self.headers.indexes.get(best_hash) if best_hash is not None else None
        if tip is None:
            raise RPCError(-32603, "Active chain is unavailable")
        current_target, negative, overflow = decode_compact_target(tip.header.bits)
        if negative or overflow or current_target <= 0:
            raise RPCError(-32603, "Active block has an invalid proof-of-work target")
        next_time = max(int(time.time()), tip.median_time_past + 1)
        try:
            next_bits = expected_work_bits(tip, next_time, self.params)
        except ValueError as exc:
            raise RPCError(-32603, "Unable to calculate next proof-of-work target") from exc
        next_target, negative, overflow = decode_compact_target(next_bits)
        if negative or overflow or next_target <= 0:
            raise RPCError(-32603, "Next block has an invalid proof-of-work target")
        result = {
            "blocks": tip.height,
            "bestblockhash": tip.block_hash[::-1].hex(),
            "bits": f"{tip.header.bits:08x}",
            "difficulty": self.params.pow_limit / current_target,
            "target": f"{current_target:064x}",
            "networkhashps": self._network_hash_ps(120, -1),
            "pooledtx": len(self.mempool.entries),
            "blockmintxfee": self.mempool.min_relay_fee_per_kvb / 100_000_000,
            "chain": self.network_name,
            "next": {
                "height": tip.height + 1,
                "bits": f"{next_bits:08x}",
                "difficulty": self.params.pow_limit / next_target,
                "target": f"{next_target:064x}",
            },
            "warnings": [],
        }
        if self.params.signet_challenge:
            result["signet_challenge"] = self.params.signet_challenge.hex()
        return result

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

    def _test_mempool_accept(
        self,
        raw_transactions: Any,
        max_fee_rate: Any,
        max_burn_amount: Any,
    ) -> list[dict[str, Any]]:
        """Evaluate a transaction package against a disposable mempool copy."""
        if self.relay is None:
            raise RPCError(-32603, "Transaction admission is not configured")
        if not isinstance(raw_transactions, list) or not raw_transactions:
            raise RPCError(-8, "rawtxs must be a non-empty array")
        if len(raw_transactions) > 25:
            raise RPCError(-8, "Package cannot exceed 25 transactions")
        if (
            isinstance(max_fee_rate, bool)
            or not isinstance(max_fee_rate, (int, float))
            or not math.isfinite(max_fee_rate)
            or max_fee_rate < 0
            or max_fee_rate > 21_000_000
        ):
            raise RPCError(-3, "maxfeerate must be a non-negative number")
        if (
            isinstance(max_burn_amount, bool)
            or not isinstance(max_burn_amount, (int, float))
            or not math.isfinite(max_burn_amount)
            or max_burn_amount < 0
            or max_burn_amount > 21_000_000
        ):
            raise RPCError(-3, "maxburnamount must be a non-negative number")

        transactions = []
        indexes: dict[bytes, int] = {}
        for position, raw_hex in enumerate(raw_transactions):
            if not isinstance(raw_hex, str):
                raise RPCError(-3, "Each raw transaction must be hexadecimal text")
            try:
                transaction = Transaction.deserialize(bytes.fromhex(raw_hex))
            except (EOFError, ValueError) as exc:
                raise RPCError(-22, "TX decode failed") from exc
            if transaction.txid in indexes:
                raise RPCError(-8, "Package contains duplicate transactions")
            indexes[transaction.txid] = position
            transactions.append(transaction)

        ordered: list[Transaction] = []
        remaining = set(indexes)
        by_txid = {transaction.txid: transaction for transaction in transactions}
        while remaining:
            ready = [
                txid
                for txid in remaining
                if not any(
                    txin.previous_output.txid in remaining
                    for txin in by_txid[txid].inputs
                )
            ]
            if not ready:
                # Keep cyclic packages in caller order; normal admission will
                # provide each transaction's concrete consensus-policy error.
                ordered.extend(
                    by_txid[txid]
                    for txid in sorted(remaining, key=indexes.__getitem__)
                )
                break
            ready.sort(key=indexes.__getitem__)
            for txid in ready:
                ordered.append(by_txid[txid])
                remaining.remove(txid)

        working = copy.deepcopy(self.mempool)
        outcomes: dict[bytes, tuple[bool, str | None, MempoolEntry | None]] = {}
        max_fee_rate_sats_per_kvb = int(max_fee_rate * 100_000_000)
        max_burn_sats = int(max_burn_amount * 100_000_000)
        for transaction in ordered:
            txid = transaction.txid
            burn = sum(
                output.value
                for output in transaction.outputs
                if output.script_pubkey.startswith(b"\x6a")
            )
            if burn > max_burn_sats:
                outcomes[txid] = (False, "max-burn-amount-exceeded", None)
                continue
            try:
                entry = working.accept(
                    transaction,
                    self.relay.coins(),
                    self.relay.height(),
                    input_verifier=self.relay.input_verifier,
                    median_time_past=self.relay.median_time_past(),
                )
            except MempoolError as exc:
                outcomes[txid] = (False, str(exc), None)
                continue
            if max_fee_rate_sats_per_kvb and entry.fee * 1_000 > max_fee_rate_sats_per_kvb * entry.vsize:
                working.remove(txid, recursive=True)
                outcomes[txid] = (False, "max-fee-exceeded", entry)
                continue
            outcomes[txid] = (True, None, entry)

        result = []
        for transaction in transactions:
            txid = transaction.txid
            allowed, reason, entry = outcomes[txid]
            if allowed and txid not in working.entries:
                allowed, reason = False, "replaced or evicted by another package transaction"
            item: dict[str, Any] = {
                "txid": txid[::-1].hex(),
                "wtxid": transaction.wtxid[::-1].hex(),
                "allowed": allowed,
            }
            if entry is not None:
                item["vsize"] = entry.vsize
                item["fees"] = {
                    "base": entry.fee / 100_000_000,
                    "effective-feerate": entry.modified_fee * 1_000 / entry.vsize / 100_000_000,
                    "effective-includes": [],
                }
            if reason is not None:
                item["reject-reason"] = reason
            result.append(item)
        return result

    def _peer_info(self, peer: PeerConnection, peer_id: int) -> dict[str, Any]:
        remote = peer.handshake.remote_version
        address = peer.address
        host = address[0] if address else ""
        services = remote.services if remote else 0
        result_address = NodeRPC._format_endpoint(host, address[1]) if address else ""
        local_socket = peer.writer.get_extra_info("sockname")
        result = {
            "id": peer.peer_id if peer.peer_id is not None else peer_id,
            "addr": result_address,
            "conntime": peer.connection_time,
            "lastsend": peer.last_send,
            "lastrecv": peer.last_receive,
            "bytessent": peer.bytes_sent,
            "bytesrecv": peer.bytes_received,
            "bytessent_per_msg": {
                command: size
                for command, size in sorted(peer.bytes_sent_per_msg.items())
                if size > 0
            },
            "bytesrecv_per_msg": {
                command: size
                for command, size in sorted(peer.bytes_received_per_msg.items())
                if size > 0
            },
            "inbound": peer.inbound,
            "connected": peer.established,
            "network": NodeRPC._peer_network(peer),
            "version": remote.protocol_version if remote else 0,
            "subver": remote.user_agent if remote else "",
            "services": f"{services:016x}",
            "servicesnames": NodeRPC._service_names(services),
            "timeoffset": peer.time_offset if peer.time_offset is not None else 0,
            "startingheight": remote.start_height if remote else -1,
            "minfeefilter": peer.fee_filter / 100_000_000,
            "connection_type": peer.connection_type,
            "transport_protocol_type": "v1",
            "bip152_hb_to": False,
            "bip152_hb_from": False,
            "presynced_headers": -1,
            "inflight": self.peer_inflight_blocks(peer),
            "addr_relay_enabled": peer.addr_relay_enabled,
            "addr_processed": peer.addr_processed,
            "addr_rate_limited": peer.addr_rate_limited,
            "permissions": [],
            "wtxidrelay": (
                peer.handshake.sent_wtxidrelay
                and peer.handshake.received_wtxidrelay
            ),
            "relaytxes": remote.relay if remote and remote.relay is not None else True,
        }
        if local_socket is not None:
            result["addrbind"] = NodeRPC._format_endpoint(str(local_socket[0]), local_socket[1])
        if remote is not None:
            local_address = remote.receiver
            if not local_address.ip.is_unspecified and local_address.port:
                result["addrlocal"] = NodeRPC._format_endpoint(
                    str(local_address.ip), local_address.port
                )
        if peer.ping_time is not None:
            result["pingtime"] = peer.ping_time
        if peer.min_ping_time is not None:
            result["minping"] = peer.min_ping_time
        ping_wait = peer.ping_wait
        if ping_wait is not None:
            result["pingwait"] = ping_wait
        return result

    @staticmethod
    def _format_endpoint(host: str, port: int) -> str:
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{host}:{port}"

    @staticmethod
    def _service_names(services: int) -> list[str]:
        names = []
        known = {
            0: "NETWORK",
            2: "BLOOM",
            3: "WITNESS",
            6: "COMPACT_FILTERS",
            10: "NETWORK_LIMITED",
            11: "P2P_V2",
        }
        for bit in range(64):
            if services & (1 << bit):
                names.append(known.get(bit, f"UNKNOWN[2^{bit}]"))
        return names

    @staticmethod
    def _peer_network(peer: PeerConnection) -> str:
        address = peer.address
        if address is None:
            return "not_publicly_routable"
        try:
            ip = ipaddress.ip_address(address[0])
        except ValueError:
            return "not_publicly_routable"
        if isinstance(ip, ipaddress.IPv4Address) or (
            isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None
        ):
            return "ipv4"
        if isinstance(ip, ipaddress.IPv6Address) and ip.packed[0] == 0xFC:
            return "cjdns"
        return "ipv6"

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
                "scriptPubKey": script_pubkey_json(coin.script_pubkey, self.network_name),
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
                    "scriptPubKey": script_pubkey_json(output.script_pubkey, self.network_name),
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
