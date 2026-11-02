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
from bitcoin_core.network.connection import PeerConnection, PeerManager
from bitcoin_core.network.messages import InventoryVector, encode_inventory
from bitcoin_core.network.version import NODE_COMPACT_FILTERS, NODE_NETWORK, NetworkAddress, VersionMessage
from bitcoin_core.node.block_sync import BlockSynchronizer
from bitcoin_core.node.chain import HeaderChain
from bitcoin_core.node.chainparams import ChainParams, get_chain_params
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
    mempool_load_result: MempoolLoadResult = field(init=False)
    relay: MempoolRelay = field(init=False)
    header_sync: HeaderSynchronizer = field(init=False)
    block_sync: BlockSynchronizer = field(init=False)
    protocol: NodeProtocol = field(init=False)
    rpc_server: RPCServer = field(init=False)
    input_verifier: ConsensusScriptVerifier = field(init=False)
    address_book: AddressBook = field(init=False)
    _manager: PeerManager | None = field(init=False, default=None)
    _peers: Callable[[], list] = field(init=False)

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = SQLiteNodeStore(self.data_dir / "chainstate.sqlite")
        self.address_book = AddressBook(self.data_dir / "peers.sqlite")
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

    def _peer_disconnected(self, peer: PeerConnection) -> None:
        """Release all per-peer synchronization state when a socket closes."""
        self.block_sync.peer_disconnected(peer)
        self.protocol.pending_header_requests.pop(peer, None)

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
            await self._manager.close()
            try:
                dump_mempool(self.data_dir / "mempool.dat", self.params.message_start, self.mempool)
            except (OSError, ValueError):
                _LOGGER.exception("Unable to persist the mempool")
            finally:
                self.address_book.close()
                self.store.close()

    async def _connect_seed(self, seed: str, port: int) -> None:
        try:
            peer = await self._manager.connect(seed, port)
            if peer.address:
                ip = ipaddress.ip_address(peer.address[0])
                address = NetworkAddress(1, ip, peer.address[1])
                self.address_book.add(address, source=seed)
                self.address_book.mark_attempt(address)
        except (OSError, asyncio.TimeoutError):
            return

    async def _maintain_peers(self) -> None:
        while True:
            self.address_book.prune()
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

