"""Startup wiring for the experimental Python full-node implementation."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from bitcoin_core.consensus.chainstate import CoinsView
from bitcoin_core.network.connection import PeerManager
from bitcoin_core.network.version import NetworkAddress, VersionMessage
from bitcoin_core.node.block_sync import BlockSynchronizer
from bitcoin_core.node.chain import HeaderChain
from bitcoin_core.node.chainparams import ChainParams, get_chain_params
from bitcoin_core.node.mempool import Mempool
from bitcoin_core.node.protocol import NodeProtocol
from bitcoin_core.node.relay import MempoolRelay
from bitcoin_core.node.rpc import NodeRPC, RPCServer
from bitcoin_core.node.storage import SQLiteNodeStore
from bitcoin_core.node.sync import HeaderSynchronizer
from bitcoin_core.script.validation import verify_transaction_input


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
    relay: MempoolRelay = field(init=False)
    header_sync: HeaderSynchronizer = field(init=False)
    block_sync: BlockSynchronizer = field(init=False)
    rpc_server: RPCServer = field(init=False)
    _manager: PeerManager | None = field(init=False, default=None)
    _peers: Callable[[], list] = field(init=False)

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = SQLiteNodeStore(self.data_dir / "chainstate.sqlite")
        self.headers = HeaderChain(self.params.consensus)
        if self.store.best_block() is None:
            index = self.headers.add_genesis(self.params.genesis.header)
            self.store.save_header(index, active=True)
            self.coins = CoinsView()
            self.store.connect_block(
                self.coins,
                self.params.genesis,
                index,
                self.params.consensus,
                input_verifier=verify_transaction_input,
            )
        else:
            self.store.load_header_chain(self.headers)
            if self.headers.indexes.get(self.params.genesis.header.block_hash) is None:
                raise ValueError("database belongs to a different Bitcoin network")
            self.coins = self.store.load_coins()

        self.mempool = Mempool()
        self._peers = lambda: list(self._manager.peers) if self._manager else []
        self.relay = MempoolRelay(
            self.mempool,
            coins=lambda: self.coins,
            height=lambda: self.store.best_height() + 1,
            median_time_past=lambda: self.headers.tip.median_time_past if self.headers.tip else 0,
            input_verifier=verify_transaction_input,
        )
        self.header_sync = HeaderSynchronizer(self.headers, magic=self.params.message_start)
        self.block_sync = BlockSynchronizer(
            self.headers,
            self.store,
            self.coins,
            self.params.consensus,
            verify_transaction_input,
        )
        protocol = NodeProtocol(self.header_sync, self.block_sync, self._peers, self.relay)
        self._manager = PeerManager(
            version_factory=self._version_for,
            magic=self.params.message_start,
            message_handler=protocol,
            disconnect_handler=self.block_sync.peer_disconnected,
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
            services=1,
            timestamp=int(time.time()),
            receiver=NetworkAddress(0, remote_ip, remote_port),
            sender=NetworkAddress(1, ipaddress.IPv4Address("0.0.0.0"), 0),
            nonce=secrets.randbits(64),
            user_agent="/bitcoin-py:0.1/",
            start_height=max(0, self.store.best_height()),
            relay=True,
        )

    async def run(self) -> None:
        """Start P2P and RPC listeners, then connect to configured DNS seeds."""
        port = self.params.default_port if self.p2p_port is None else self.p2p_port
        await self._manager.listen(self.p2p_host, port)
        await self.rpc_server.start()
        try:
            await asyncio.gather(*(self._connect_seed(seed, port) for seed in self.params.dns_seeds))
            await asyncio.Event().wait()
        finally:
            await self.rpc_server.close()
            await self._manager.close()
            self.store.close()

    async def _connect_seed(self, seed: str, port: int) -> None:
        try:
            await self._manager.connect(seed, port)
        except (OSError, asyncio.TimeoutError):
            return


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

