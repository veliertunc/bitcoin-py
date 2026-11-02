"""Async TCP peer connections and a small peer manager."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from bitcoin_core.network.peer import PeerHandshake, PeerState
from bitcoin_core.network.protocol import MAINNET_MAGIC, Message, MessageParser, encode_message
from bitcoin_core.network.version import VersionMessage

MessageHandler = Callable[["PeerConnection", Message], object | Awaitable[object]]
VersionFactory = Callable[[tuple | None], VersionMessage]
DisconnectHandler = Callable[["PeerConnection"], object | Awaitable[object]]


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
    handshake: PeerHandshake = field(init=False)
    parser: MessageParser = field(init=False)
    _closed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.handshake = PeerHandshake(self.local_version.nonce, self.magic)
        self.parser = MessageParser(self.magic, max_payload=self.max_payload)

    @property
    def address(self) -> tuple | None:
        return self.writer.get_extra_info("peername")

    @property
    def established(self) -> bool:
        return self.handshake.state is PeerState.ESTABLISHED

    async def send(self, command: str, payload: bytes = b"") -> None:
        """Send an application message after the version handshake completes."""
        if self._closed or not self.established:
            raise ConnectionError("peer is not established")
        await self._write(encode_message(command, payload, self.magic))

    async def _write(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionError("peer connection is closed")
        self.writer.write(data)
        await self.writer.drain()

    async def run(self) -> None:
        """Send version, process incoming frames, and close when the stream ends."""
        try:
            await self._write(self.handshake.start(self.local_version))
            while data := await self.reader.read(64 * 1024):
                for message in self.parser.feed(data):
                    was_established = self.established
                    replies = self.handshake.receive(message)
                    for reply in replies:
                        await self._write(reply)
                    if not was_established and self.established:
                        await self._notify(message)
                        continue
                    if not self.established:
                        continue
                    if message.command == "ping":
                        if len(message.payload) != 8:
                            raise ConnectionError("malformed ping payload")
                        await self._write(encode_message("pong", message.payload, self.magic))
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
    peers: set[PeerConnection] = field(default_factory=set, init=False)
    _tasks: set[asyncio.Task] = field(default_factory=set, init=False)
    _server: asyncio.AbstractServer | None = field(default=None, init=False)

    async def listen(self, host: str, port: int) -> None:
        """Start accepting inbound P2P connections."""
        if self._server is not None:
            raise RuntimeError("peer listener is already running")
        self._server = await asyncio.start_server(self._accept, host, port)

    async def connect(self, host: str, port: int) -> PeerConnection:
        """Open an outbound connection and begin its handshake task."""
        reader, writer = await asyncio.open_connection(host, port)
        return self._track(reader, writer, inbound=False)

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
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
    ) -> PeerConnection:
        peer = PeerConnection(
            reader,
            writer,
            self.version_factory(writer.get_extra_info("peername")),
            self.magic,
            self.message_handler,
            inbound=inbound,
        )
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
