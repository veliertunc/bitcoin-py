"""Async TCP peer connections and a small peer manager."""

from __future__ import annotations

import asyncio
import inspect
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from bitcoin_core.network.peer import PeerHandshake, PeerState
from bitcoin_core.network.protocol import MAINNET_MAGIC, Message, MessageParser, encode_message
from bitcoin_core.network.version import VersionMessage

MessageHandler = Callable[["PeerConnection", Message], object | Awaitable[object]]
VersionFactory = Callable[[tuple | None], VersionMessage]
DisconnectHandler = Callable[["PeerConnection"], object | Awaitable[object]]
AddressFilter = Callable[[tuple | None], bool]


@dataclass(eq=False, slots=True)
class PeerConnection:
    """One asynchronous TCP connection using Bitcoin P2P framing."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    local_version: VersionMessage
    magic: bytes = MAINNET_MAGIC
    message_handler: MessageHandler | None = None
    max_payload: int = 32 * 1024 * 1024
    inbound: bool = False
    handshake_timeout: float = 60.0
    fee_filter: int = 0
    prefers_headers: bool = False
    ping_interval: float = 120.0
    ping_timeout: float = 1_200.0
    ping_time: float | None = None
    peer_id: int | None = None
    destination: tuple[str, int] | None = None
    connection_type: str = "outbound-full-relay"
    min_ping_time: float | None = None
    time_offset: int | None = None
    bytes_sent: int = field(default=0, init=False)
    bytes_received: int = field(default=0, init=False)
    bytes_sent_per_msg: dict[str, int] = field(default_factory=dict, init=False)
    bytes_received_per_msg: dict[str, int] = field(default_factory=dict, init=False)
    connection_time: int = field(init=False)
    last_send: int = field(init=False)
    last_receive: int = field(init=False)
    requested_transactions: set[tuple[int, bytes]] = field(default_factory=set, init=False)
    getaddr_received: bool = field(default=False, init=False)
    addr_processed: int = field(default=0, init=False)
    addr_rate_limited: int = field(default=0, init=False)
    addr_relay_enabled: bool = field(default=False, init=False)
    known_addresses: set[tuple[int, bytes, int]] = field(default_factory=set, init=False)
    handshake: PeerHandshake = field(init=False)
    parser: MessageParser = field(init=False)
    _closed: bool = field(default=False, init=False)
    _ever_established: bool = field(default=False, init=False)
    _handshake_started_at: float = field(init=False)
    _next_ping_at: float = field(init=False)
    _ping_nonce: int | None = field(default=None, init=False)
    _ping_sent_at: float | None = field(default=None, init=False)
    _addr_token_bucket: float = field(default=1.0, init=False)
    _addr_token_timestamp: float = field(init=False)

    def __post_init__(self) -> None:
        if self.handshake_timeout <= 0 or self.ping_interval <= 0 or self.ping_timeout <= 0:
            raise ValueError("peer timeouts and ping intervals must be positive")
        self.handshake = PeerHandshake(self.local_version.nonce, self.magic)
        self.parser = MessageParser(self.magic, max_payload=self.max_payload)
        now = int(time.time())
        self.connection_time = now
        self.last_send = now
        self.last_receive = now
        self._addr_token_timestamp = time.monotonic()
        self._handshake_started_at = time.monotonic()
        self._next_ping_at = time.monotonic() + self.ping_interval

    @property
    def address(self) -> tuple | None:
        return self.writer.get_extra_info("peername")

    @property
    def established(self) -> bool:
        return self.handshake.state is PeerState.ESTABLISHED

    @property
    def ever_established(self) -> bool:
        """Whether the peer completed its handshake before the socket closed."""
        return self._ever_established or self.established

    @property
    def ping_wait(self) -> float | None:
        """Elapsed seconds since the outstanding ping was sent, if any."""
        if self._ping_sent_at is None:
            return None
        return max(0.0, time.monotonic() - self._ping_sent_at)

    async def send(self, command: str, payload: bytes = b"") -> None:
        """Send an application message after the version handshake completes."""
        if self._closed or not self.established:
            raise ConnectionError("peer is not established")
        await self._write(encode_message(command, payload, self.magic))

    async def request_ping(self) -> bool:
        """Request an immediate RTT sample unless another ping is outstanding."""
        if self._closed or not self.established or self._ping_sent_at is not None:
            return False
        nonce = secrets.randbits(64) or 1
        self._ping_nonce = nonce
        self._ping_sent_at = time.monotonic()
        self._next_ping_at = self._ping_sent_at + self.ping_interval
        try:
            await self.send("ping", nonce.to_bytes(8, "little"))
        except (ConnectionError, OSError):
            self._ping_nonce = None
            self._ping_sent_at = None
            return False
        return True

    def add_address_tokens(self, count: int) -> None:
        """Add a bounded one-time allowance for a requested address response."""
        self._refill_address_tokens()
        self._addr_token_bucket = min(1_000.0, self._addr_token_bucket + max(0, count))

    def consume_address_token(self) -> bool:
        """Consume one address-processing token, returning false when rate-limited."""
        self._refill_address_tokens()
        if self._addr_token_bucket < 1.0:
            self.addr_rate_limited += 1
            return False
        self._addr_token_bucket -= 1.0
        return True

    def _refill_address_tokens(self) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self._addr_token_timestamp)
        self._addr_token_bucket = min(1_000.0, self._addr_token_bucket + elapsed * 0.1)
        self._addr_token_timestamp = now

    def remember_address(self, key: tuple[int, bytes, int]) -> None:
        """Remember a bounded set of addresses already seen on this connection."""
        if key in self.known_addresses:
            return
        if len(self.known_addresses) >= 5_000:
            self.known_addresses.pop()
        self.known_addresses.add(key)

    async def _write(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionError("peer connection is closed")
        self.writer.write(data)
        await self.writer.drain()
        self.bytes_sent += len(data)
        if len(data) >= 24 and data[:4] == self.magic:
            command = data[4:16].split(b"\0", 1)[0].decode("ascii", errors="replace")
            self.bytes_sent_per_msg[command] = self.bytes_sent_per_msg.get(command, 0) + len(data)
        self.last_send = int(time.time())

    async def run(self) -> None:
        """Send version, process incoming frames, and close when the stream ends."""
        try:
            await self._write(self.handshake.start(self.local_version))
            await self._write(encode_message("sendaddrv2", b"", self.magic))
            self.handshake.sent_addrv2 = True
            if self.local_version.protocol_version >= 70_016:
                await self._write(encode_message("wtxidrelay", b"", self.magic))
                self.handshake.sent_wtxidrelay = True
            self._handshake_started_at = time.monotonic()
            while not self._closed:
                timeout = None
                if not self.established:
                    timeout = self.handshake_timeout - (time.monotonic() - self._handshake_started_at)
                    if timeout <= 0:
                        raise ConnectionError("peer handshake timed out")
                else:
                    now = time.monotonic()
                    if self._ping_sent_at is not None:
                        timeout = self.ping_timeout - (now - self._ping_sent_at)
                        if timeout <= 0:
                            raise ConnectionError("peer ping timed out")
                    else:
                        timeout = max(0.0, self._next_ping_at - now)
                try:
                    data = await asyncio.wait_for(self.reader.read(64 * 1024), timeout)
                except TimeoutError:
                    if not self.established:
                        raise ConnectionError("peer handshake timed out")
                    if self._ping_sent_at is not None:
                        if time.monotonic() - self._ping_sent_at >= self.ping_timeout:
                            raise ConnectionError("peer ping timed out")
                        continue
                    self._ping_nonce = secrets.randbits(64) or 1
                    self._ping_sent_at = time.monotonic()
                    self._next_ping_at = self._ping_sent_at + self.ping_interval
                    await self._write(
                        encode_message("ping", self._ping_nonce.to_bytes(8, "little"), self.magic)
                    )
                    continue
                if not data:
                    break
                self.bytes_received += len(data)
                self.last_receive = int(time.time())
                for message in self.parser.feed(data):
                    self.bytes_received_per_msg[message.command] = (
                        self.bytes_received_per_msg.get(message.command, 0) + message.wire_size
                    )
                    was_established = self.established
                    replies = self.handshake.receive(message)
                    if self.established:
                        self._ever_established = True
                    if message.command == "version" and self.handshake.remote_version is not None:
                        self.time_offset = self.handshake.remote_version.timestamp - int(time.time())
                    for reply in replies:
                        await self._write(reply)
                    if not was_established and self.established:
                        self._next_ping_at = time.monotonic() + self.ping_interval
                        await self._notify(message)
                        continue
                    if not self.established:
                        continue
                    if message.command == "ping":
                        if len(message.payload) != 8:
                            raise ConnectionError("malformed ping payload")
                        await self._write(encode_message("pong", message.payload, self.magic))
                    elif message.command == "pong":
                        if len(message.payload) != 8:
                            continue
                        if self._ping_nonce is not None and int.from_bytes(message.payload, "little") == self._ping_nonce:
                            sent_at = self._ping_sent_at
                            if sent_at is not None:
                                self.ping_time = max(0.0, time.monotonic() - sent_at)
                                if self.min_ping_time is None or self.ping_time < self.min_ping_time:
                                    self.min_ping_time = self.ping_time
                            self._ping_nonce = None
                            self._ping_sent_at = None
                            self._next_ping_at = time.monotonic() + self.ping_interval
                    elif message.command == "verack":
                        continue
                    else:
                        await self._notify(message)
        finally:
            await self.close()

    async def _notify(self, message: Message) -> None:
        if self.message_handler is None:
            return
        result = self.message_handler(self, message)
        if inspect.isawaitable(result):
            await result

    async def close(self) -> None:
        """Close the stream and mark its handshake state closed."""
        if self._closed:
            return
        self._closed = True
        self.handshake.close()
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass


@dataclass(slots=True)
class PeerManager:
    """Manage inbound listeners, outbound connections, and peer tasks."""

    version_factory: VersionFactory
    magic: bytes = MAINNET_MAGIC
    message_handler: MessageHandler | None = None
    disconnect_handler: DisconnectHandler | None = None
    max_inbound: int = 125
    network_active: bool = True
    address_filter: AddressFilter | None = None
    peers: set[PeerConnection] = field(default_factory=set, init=False)
    bytes_sent_total: int = field(default=0, init=False)
    bytes_received_total: int = field(default=0, init=False)
    _tasks: set[asyncio.Task] = field(default_factory=set, init=False)
    _server: asyncio.AbstractServer | None = field(default=None, init=False)
    _next_peer_id: int = field(default=0, init=False)

    async def listen(self, host: str, port: int) -> None:
        """Start accepting inbound P2P connections."""
        if self._server is not None:
            raise RuntimeError("peer listener is already running")
        self._server = await asyncio.start_server(self._accept, host, port)

    async def connect(
        self,
        host: str,
        port: int,
        *,
        connection_type: str = "outbound-full-relay",
    ) -> PeerConnection:
        """Open an outbound connection and begin its handshake task."""
        if not self.network_active:
            raise ConnectionError("P2P networking is disabled")
        if self.address_filter is not None and not self.address_filter((host, port)):
            raise ConnectionError("outbound peer address is banned")
        reader, writer = await asyncio.open_connection(host, port)
        if not self.network_active:
            writer.close()
            await writer.wait_closed()
            raise ConnectionError("P2P networking was disabled during connection setup")
        if self.address_filter is not None and not self.address_filter(writer.get_extra_info("peername")):
            writer.close()
            await writer.wait_closed()
            raise ConnectionError("outbound peer address is banned")
        return self._track(
            reader,
            writer,
            inbound=False,
            destination=(host, port),
            connection_type=connection_type,
        )

    def set_network_active(self, active: bool) -> bool:
        """Enable or disable new inbound and outbound P2P connections."""
        if not isinstance(active, bool):
            raise TypeError("network active state must be a boolean")
        self.network_active = active
        return self.network_active

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self.network_active or (
            self.address_filter is not None
            and not self.address_filter(writer.get_extra_info("peername"))
        ):
            writer.close()
            await writer.wait_closed()
            return
        inbound_count = sum(1 for peer in self.peers if peer.inbound)
        if inbound_count >= self.max_inbound:
            writer.close()
            await writer.wait_closed()
            return
        self._track(reader, writer, inbound=True)

    def _track(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        inbound: bool,
        destination: tuple[str, int] | None = None,
        connection_type: str | None = None,
    ) -> PeerConnection:
        peer = PeerConnection(
            reader,
            writer,
            self.version_factory(writer.get_extra_info("peername")),
            self.magic,
            self.message_handler,
            inbound=inbound,
            peer_id=self._next_peer_id,
            destination=destination,
            connection_type=connection_type or ("inbound" if inbound else "outbound-full-relay"),
        )
        self._next_peer_id += 1
        self.peers.add(peer)
        task = asyncio.create_task(self._run_peer(peer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return peer

    async def _run_peer(self, peer: PeerConnection) -> None:
        try:
            await peer.run()
        except (ConnectionError, OSError, ValueError):
            await peer.close()
        finally:
            self.bytes_sent_total += peer.bytes_sent
            self.bytes_received_total += peer.bytes_received
            self.peers.discard(peer)
            if self.disconnect_handler is not None:
                result = self.disconnect_handler(peer)
                if inspect.isawaitable(result):
                    await result

    async def close(self) -> None:
        """Stop accepting connections and close all managed peers."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        await asyncio.gather(*(peer.close() for peer in tuple(self.peers)), return_exceptions=True)
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
