"""Startup wiring for the experimental Python full-node implementation."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from bitcoin_core.consensus.chainstate import CoinsView
from bitcoin_core.network.addrman import AddressBook
from bitcoin_core.network.banman import BanManager
from bitcoin_core.network.connection import PeerConnection, PeerManager
from bitcoin_core.network.endpoint import NodeEndpoint, parse_node_endpoint
from bitcoin_core.network.messages import InventoryVector, encode_inventory
from bitcoin_core.network.version import NODE_COMPACT_FILTERS, NODE_NETWORK, NetworkAddress, VersionMessage
from bitcoin_core.node.block_sync import BlockSynchronizer
from bitcoin_core.node.chain import HeaderChain
from bitcoin_core.node.chainparams import ChainParams, get_chain_params
from bitcoin_core.node.fee_estimator import MempoolFeeEstimator
from bitcoin_core.node.block_policy_estimator import BlockPolicyEstimator
from bitcoin_core.node.mempool import Mempool, MempoolError
from bitcoin_core.node.mempool_persistence import (
    MempoolLoadResult,
    dump_mempool,
    load_mempool,
)
from bitcoin_core.node.protocol import NodeProtocol
from bitcoin_core.node.relay import MempoolRelay
from bitcoin_core.node.rpc import NodeRPC, RPCServer
from bitcoin_core.node.storage import SQLiteNodeStore
from bitcoin_core.node.sync import HeaderSynchronizer
from bitcoin_core.primitives.block import Block
from bitcoin_core.script.validation import ConsensusScriptVerifier

_LOGGER = logging.getLogger(__name__)
MAX_ADDED_NODE_CONNECTIONS = 8


@dataclass(slots=True)
class BitcoinNode:
    """Own the services and state needed to run the Python node."""

    params: ChainParams
    data_dir: Path
    p2p_host: str = "0.0.0.0"
    p2p_port: int | None = None
    rpc_host: str = "127.0.0.1"
    rpc_port: int | None = None
    store: SQLiteNodeStore = field(init=False)
    headers: HeaderChain = field(init=False)
    coins: CoinsView = field(init=False)
    mempool: Mempool = field(init=False)
    fee_estimator: MempoolFeeEstimator = field(init=False)
    block_policy_estimator: BlockPolicyEstimator = field(init=False)
    mempool_load_result: MempoolLoadResult = field(init=False)
    relay: MempoolRelay = field(init=False)
    header_sync: HeaderSynchronizer = field(init=False)
    block_sync: BlockSynchronizer = field(init=False)
    protocol: NodeProtocol = field(init=False)
    rpc_server: RPCServer = field(init=False)
    input_verifier: ConsensusScriptVerifier = field(init=False)
    address_book: AddressBook = field(init=False)
    ban_manager: BanManager = field(init=False)
    _manager: PeerManager | None = field(init=False, default=None)
    _peers: Callable[[], list] = field(init=False)
    _added_nodes: dict[tuple[str, int], tuple[str, NodeEndpoint]] = field(init=False, default_factory=dict)
    _added_connecting: set[tuple[str, int]] = field(init=False, default_factory=set)
    _added_tasks: set[asyncio.Task] = field(init=False, default_factory=set)

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = SQLiteNodeStore(self.data_dir / "chainstate.sqlite")
        self.address_book = AddressBook(self.data_dir / "peers.sqlite")
        self.ban_manager = BanManager(self.data_dir / "banlist.sqlite")
        self.headers = HeaderChain(self.params.consensus)
        self.input_verifier = ConsensusScriptVerifier(self.params.consensus)
        if self.store.best_block() is None:
            index = self.headers.add_genesis(self.params.genesis.header)
            self.store.save_header(index, active=True)
            self.coins = CoinsView()
            self.store.connect_block(
                self.coins,
                self.params.genesis,
                index,
                self.params.consensus,
                input_verifier=self.input_verifier,
            )
        else:
            self.store.load_header_chain(self.headers)
            if self.headers.indexes.get(self.params.genesis.header.block_hash) is None:
                raise ValueError("database belongs to a different Bitcoin network")
            self.store.remove_unspendable_genesis_coinbase(self.params.genesis)
            self.coins = self.store.load_coins(self.headers)

        self.mempool = Mempool()
        self.mempool_load_result = load_mempool(
            self.data_dir / "mempool.dat",
            self.params.message_start,
            self.mempool,
            self.coins,
            self.store.best_height() + 1,
            median_time_past=self.headers.tip.median_time_past if self.headers.tip else 0,
            input_verifier=self.input_verifier,
        )
        if self.mempool_load_result.reason is not None:
            _LOGGER.warning("Mempool snapshot was ignored: %s", self.mempool_load_result.reason)
        self.fee_estimator = MempoolFeeEstimator(self.data_dir / "fee-estimator.sqlite", self.mempool)
        self.block_policy_estimator = BlockPolicyEstimator(
            self.data_dir / "fee-estimates.sqlite"
        )
        self.block_policy_estimator.best_height = self.store.best_height()
        self.mempool.transaction_added = lambda entry: self.block_policy_estimator.process_transaction(
            entry, self.store.best_height()
        )
        self.mempool.transaction_removed = self.block_policy_estimator.remove_transaction
        self._peers = lambda: list(self._manager.peers) if self._manager else []
        self.relay = MempoolRelay(
            self.mempool,
            coins=lambda: self.coins,
            height=lambda: self.store.best_height() + 1,
            median_time_past=lambda: self.headers.tip.median_time_past if self.headers.tip else 0,
            input_verifier=self.input_verifier,
        )
        self.header_sync = HeaderSynchronizer(
            self.headers,
            magic=self.params.message_start,
            persist_header=self.store.save_header,
        )
        self.block_sync = BlockSynchronizer(
            self.headers,
            self.store,
            self.coins,
            self.params.consensus,
            self.input_verifier,
            activation_handler=self._handle_chain_activation,
        )
        self.protocol = NodeProtocol(
            self.header_sync,
            self.block_sync,
            self._peers,
            self.relay,
            self.address_book,
        )
        self._manager = PeerManager(
            version_factory=self._version_for,
            magic=self.params.message_start,
            message_handler=self.protocol,
            disconnect_handler=self._peer_disconnected,
            address_filter=self._peer_address_allowed,
        )
        rpc = NodeRPC(
            self.store,
            self.headers,
            self.coins,
            self.params.consensus,
            self.mempool,
            self.relay,
            self.params.name,
            self._peers,
            self._submit_block,
            self.block_sync.test_block,
            self._dump_mempool,
            self._import_mempool,
            self._network_totals,
            self.address_book,
            self._network_active,
            self._set_network_active,
            self._disconnect_peer,
            self._manage_added_node,
            self._added_node_info,
            self.ban_manager,
            self._disconnect_banned,
            self._peer_inflight_blocks,
            fee_estimator=self.fee_estimator,
            block_policy_estimator=self.block_policy_estimator,
        )
        self.rpc_server = RPCServer(
            rpc,
            self.data_dir / ".cookie",
            self.rpc_host,
            self.params.rpc_port if self.rpc_port is None else self.rpc_port,
        )

    def _version_for(self, remote: tuple | None) -> VersionMessage:
        remote_host = remote[0] if remote else "0.0.0.0"
        remote_port = remote[1] if remote and len(remote) > 1 else self.params.default_port
        try:
            remote_ip = ipaddress.ip_address(remote_host)
        except ValueError:
            remote_ip = ipaddress.IPv4Address("0.0.0.0")
        return VersionMessage(
            protocol_version=70_016,
            services=NODE_NETWORK | NODE_COMPACT_FILTERS,
            timestamp=int(time.time()),
            receiver=NetworkAddress(0, remote_ip, remote_port),
            sender=NetworkAddress(1, ipaddress.IPv4Address("0.0.0.0"), 0),
            nonce=secrets.randbits(64),
            user_agent="/bitcoin-py:0.1/",
            start_height=max(0, self.store.best_height()),
            relay=True,
        )

    def _network_totals(self) -> tuple[int, int]:
        """Return traffic totals from peer connections that have already closed."""
        if self._manager is None:
            return 0, 0
        return self._manager.bytes_sent_total, self._manager.bytes_received_total

    def _peer_inflight_blocks(self, peer: PeerConnection) -> list[int]:
        return sorted(
            index.height
            for block_hash, owner in self.block_sync.in_flight.items()
            if owner is peer
            and (index := self.headers.indexes.get(block_hash)) is not None
        )

    def _network_active(self) -> bool:
        return self._manager.network_active if self._manager is not None else False

    def _set_network_active(self, active: bool) -> bool:
        if self._manager is None:
            return False
        return self._manager.set_network_active(active)

    def _peer_address_allowed(self, remote: tuple | None) -> bool:
        if remote is None:
            return True
        try:
            return not self.ban_manager.is_banned(remote[0])
        except (IndexError, TypeError):
            return True

    async def _disconnect_banned(self, subnet) -> None:
        for peer in tuple(self._peers()):
            remote = peer.address
            if remote is None:
                continue
            try:
                ip = ipaddress.ip_address(remote[0])
            except ValueError:
                continue
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
            if ip.version == subnet.version and ip in subnet:
                await peer.close()

    @staticmethod
    def _added_node_key(endpoint: NodeEndpoint) -> tuple[str, int]:
        return endpoint.host.lower(), endpoint.port

    def _schedule_added_connection(self, endpoint: NodeEndpoint) -> None:
        if self._manager is None or not self._manager.network_active:
            return
        key = self._added_node_key(endpoint)
        if key in self._added_connecting or any(
            peer.destination is not None
            and (peer.destination[0].lower(), peer.destination[1]) == key
            for peer in self._manager.peers
        ):
            return
        active_added = sum(
            1
            for peer in self._manager.peers
            if peer.destination is not None
            and (peer.destination[0].lower(), peer.destination[1]) in self._added_nodes
        )
        if active_added + len(self._added_connecting) >= MAX_ADDED_NODE_CONNECTIONS:
            return
        self._added_connecting.add(key)
        task = asyncio.create_task(self._connect_added_node(endpoint))
        self._added_tasks.add(task)
        task.add_done_callback(lambda completed: self._finish_added_task(completed, key))

    def _finish_added_task(self, task: asyncio.Task, key: tuple[str, int]) -> None:
        self._added_tasks.discard(task)
        self._added_connecting.discard(key)

    async def _connect_added_node(self, endpoint: NodeEndpoint) -> None:
        if self._manager is None or not self._manager.network_active:
            return
        try:
            await self._manager.connect(
                endpoint.host,
                endpoint.port,
                connection_type="manual",
            )
        except (ConnectionError, OSError, asyncio.TimeoutError):
            return

    async def _manage_added_node(self, specification: str, command: str) -> None:
        if command not in {"add", "remove", "onetry"}:
            raise ValueError("command must be add, remove, or onetry")
        try:
            endpoint = parse_node_endpoint(specification, self.params.default_port)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        key = self._added_node_key(endpoint)
        if command == "add":
            if key in self._added_nodes:
                raise ValueError("Node already added")
            self._added_nodes[key] = (specification, endpoint)
            self._schedule_added_connection(endpoint)
        elif command == "remove":
            if key not in self._added_nodes:
                raise ValueError("Node has not been added")
            del self._added_nodes[key]
        else:
            self._schedule_added_connection(endpoint)

    def _added_node_info(self, specification: str | None = None) -> list[dict]:
        entries = self._added_nodes.values()
        if specification is not None:
            try:
                endpoint = parse_node_endpoint(specification, self.params.default_port)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
            entry = self._added_nodes.get(self._added_node_key(endpoint))
            if entry is None:
                raise ValueError("Node has not been added")
            entries = (entry,)
        result = []
        for original, endpoint in entries:
            key = self._added_node_key(endpoint)
            connected = []
            for peer in self._peers():
                destination = peer.destination
                if destination is None or (destination[0].lower(), destination[1]) != key:
                    continue
                remote = peer.address
                host, port = (str(remote[0]), remote[1]) if remote else destination
                connected.append({"address": f"{host}:{port}", "connected": "outbound"})
            item = {"addednode": original, "connected": bool(connected)}
            if connected:
                item["addresses"] = connected
            result.append(item)
        return result

    async def _disconnect_peer(self, address: str | None, peer_id: int | None) -> bool:
        if self._manager is None:
            return False
        host_filter: str | None = None
        port_filter: int | None = None
        if address is not None:
            candidate = address
            if candidate.startswith("[") and "]" in candidate:
                close = candidate.index("]")
                host_filter = candidate[1:close]
                suffix = candidate[close + 1 :]
                if suffix:
                    if not suffix.startswith(":") or not suffix[1:].isdecimal():
                        return False
                    port_filter = int(suffix[1:])
            else:
                try:
                    host_filter = str(ipaddress.ip_address(candidate))
                except ValueError:
                    host, separator, port_text = candidate.rpartition(":")
                    if separator and port_text.isdecimal():
                        host_filter = host
                        port_filter = int(port_text)
                    else:
                        host_filter = candidate
        for peer in tuple(self._manager.peers):
            if peer_id is not None and peer.peer_id != peer_id:
                continue
            if host_filter is not None:
                remote = peer.address
                if remote is None or str(remote[0]).lower() != host_filter.lower():
                    continue
                if port_filter is not None and remote[1] != port_filter:
                    continue
            await peer.close()
            return True
        return False

    async def _submit_block(self, block: Block) -> str | None:
        """Submit a mined block through the same chain activation path as P2P blocks."""
        status = await self.block_sync.accept_local_block(block)
        if status is None:
            announcement = encode_inventory(
                [InventoryVector(2, block.header.block_hash)]
            )
            for peer in self._peers():
                if peer.established:
                    try:
                        await peer.send("inv", announcement)
                    except (ConnectionError, OSError):
                        continue
        return status

    async def _handle_chain_activation(
        self,
        disconnected: tuple[Block, ...],
        connected: tuple[Block, ...],
    ) -> None:
        """Reconcile pending transactions after an active-chain switch."""
        connected_transactions = tuple(
            transaction
            for block in connected
            for transaction in block.transactions
        )
        pending_mempool_ids = set(self.mempool.entries)

        def discard_mempool_descendants(txid: bytes) -> None:
            stack = [txid]
            while stack:
                current = stack.pop()
                if current not in pending_mempool_ids:
                    continue
                pending_mempool_ids.discard(current)
                entry = self.mempool.entries.get(current)
                if entry is not None:
                    stack.extend(entry.children)

        for block in connected:
            index = self.headers.indexes.get(block.header.block_hash)
            if index is None:
                continue
            block_weight = 0
            removed_weight = 0
            block_txids = {transaction.txid for transaction in block.transactions}
            for transaction in block.transactions[1:]:
                for txin in transaction.inputs:
                    conflicting = self.mempool.spent_outpoints.get(
                        (txin.previous_output.txid, txin.previous_output.index)
                    )
                    if conflicting is not None and conflicting not in block_txids:
                        discard_mempool_descendants(conflicting)
                raw = transaction.serialize(include_witness=True)
                stripped = transaction.serialize(include_witness=False)
                weight = len(stripped) * 3 + len(raw)
                block_weight += weight
                if transaction.txid in pending_mempool_ids:
                    removed_weight += weight
                    pending_mempool_ids.discard(transaction.txid)
            self.fee_estimator.record_block(
                index.height,
                index.block_hash,
                block.header.previous_block,
                block_weight,
                removed_weight,
            )
            self.block_policy_estimator.process_block(
                index.height,
                tuple(transaction.txid for transaction in block.transactions[1:]),
            )
        self.mempool.remove_for_block(connected_transactions)
        self.mempool.revalidate(
            self.coins,
            self.store.best_height() + 1,
            input_verifier=self.input_verifier,
            median_time_past=self.headers.tip.median_time_past if self.headers.tip else 0,
        )
        # Disconnected blocks are supplied oldest first, so parents are offered
        # before their children when restoring transactions to the pool.
        for block in disconnected:
            for transaction in block.transactions[1:]:
                try:
                    await self.relay.submit(transaction, self._peers())
                except MempoolError:
                    continue
        await self.relay.rebroadcast_unbroadcast(self._peers())

    def _peer_disconnected(self, peer: PeerConnection) -> None:
        """Release all per-peer synchronization state when a socket closes."""
        # Addrman success means the peer completed the protocol handshake. A
        # TCP connection that never reaches that point must keep its failure
        # penalty so it is not repeatedly selected ahead of healthier peers.
        if peer.ever_established and peer.address is not None:
            try:
                remote_ip = ipaddress.ip_address(peer.address[0])
                self.address_book.mark_success(
                    NetworkAddress(0, remote_ip, peer.address[1])
                )
            except ValueError:
                pass
        self.block_sync.peer_disconnected(peer)
        self.protocol.pending_header_requests.pop(peer, None)
        self.relay.orphanage.remove_peer(peer)

    def _dump_mempool(self) -> str:
        """Persist the current transaction pool and return its file path."""
        path = self.data_dir / "mempool.dat"
        dump_mempool(path, self.params.message_start, self.mempool)
        return str(path)

    def _import_mempool(self, filename: str, options: dict[str, bool]) -> MempoolLoadResult:
        """Load a snapshot into the existing pool after current-chain revalidation."""
        return load_mempool(
            filename,
            self.params.message_start,
            self.mempool,
            self.coins,
            self.store.best_height() + 1,
            median_time_past=self.headers.tip.median_time_past if self.headers.tip else 0,
            input_verifier=self.input_verifier,
            use_current_time=options["use_current_time"],
            apply_unbroadcast_set=options["apply_unbroadcast_set"],
            apply_fee_delta_priority=options["apply_fee_delta_priority"],
            missing_ok=False,
        )

    async def run(self) -> None:
        """Start P2P and RPC listeners, then connect to configured DNS seeds."""
        try:
            port = self.params.default_port if self.p2p_port is None else self.p2p_port
            await self._manager.listen(self.p2p_host, port)
            await self.rpc_server.start()
            await asyncio.gather(*(self._connect_seed(seed, port) for seed in self.params.dns_seeds))
            maintenance = asyncio.create_task(self._maintain_peers())
            try:
                await asyncio.Event().wait()
            finally:
                maintenance.cancel()
                await asyncio.gather(maintenance, return_exceptions=True)
        finally:
            await self.rpc_server.close()
            for task in tuple(self._added_tasks):
                task.cancel()
            if self._added_tasks:
                await asyncio.gather(*tuple(self._added_tasks), return_exceptions=True)
            await self._manager.close()
            try:
                dump_mempool(self.data_dir / "mempool.dat", self.params.message_start, self.mempool)
            except (OSError, ValueError):
                _LOGGER.exception("Unable to persist the mempool")
            finally:
                self.address_book.close()
                self.ban_manager.close()
                self.fee_estimator.close()
                self.block_policy_estimator.close()
                self.store.close()

    async def _connect_seed(self, seed: str, port: int) -> None:
        try:
            peer = await self._manager.connect(seed, port)
            if peer.address:
                ip = ipaddress.ip_address(peer.address[0])
                address = NetworkAddress(1, ip, peer.address[1])
                self.address_book.add(address, source=seed)
                # The socket is live; the disconnect callback records the
                # protocol-level success after the handshake completes.
        except (OSError, asyncio.TimeoutError):
            return

    async def _maintain_peers(self) -> None:
        while True:
            self.block_policy_estimator.flush()
            self.address_book.prune()
            self.ban_manager.prune()
            if not self._manager.network_active:
                await asyncio.sleep(30)
                continue
            for _, endpoint in self._added_nodes.values():
                self._schedule_added_connection(endpoint)
            outbound = [peer for peer in self._manager.peers if not peer.inbound]
            target = max(0, 8 - len(outbound))
            if target:
                connected = {
                    (str(peer.address[0]), peer.address[1])
                    for peer in self._manager.peers
                    if peer.address is not None
                }
                for record in self.address_book.select(max(target * 3, target)):
                    address = record.address
                    key = (str(address.ip), address.port)
                    if key in connected:
                        continue
                    self.address_book.mark_attempt(address)
                    try:
                        await self._manager.connect(str(address.ip), address.port)
                    except (OSError, asyncio.TimeoutError):
                        continue
                    connected.add(key)
                    target -= 1
                    if target == 0:
                        break
            await asyncio.sleep(30)


def main() -> None:
    parser = argparse.ArgumentParser(description="Experimental modular Python Bitcoin node")
    parser.add_argument("--network", choices=("main", "test", "testnet4", "signet", "regtest"), default="main")
    parser.add_argument("--datadir", type=Path, default=Path.home() / ".bitcoin-py")
    parser.add_argument("--p2p-host", default="0.0.0.0")
    parser.add_argument("--p2p-port", type=int)
    parser.add_argument("--rpc-host", default="127.0.0.1")
    parser.add_argument("--rpc-port", type=int)
    args = parser.parse_args()
    node = BitcoinNode(
        get_chain_params(args.network),
        args.datadir / args.network,
        args.p2p_host,
        args.p2p_port,
        args.rpc_host,
        args.rpc_port,
    )
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        pass

